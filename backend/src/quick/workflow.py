"""Quick workflow DAG: stage order, task dependencies, phase allowlist.

Maps Quick stages onto the existing 8-phase ``ScanStateMachine``. Skipped
phases are ``not_scheduled_by_quick_profile``, never ``failed``.
"""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from typing import Any

from pydantic import ValidationError

from src.execution_mode.mode import ExecutionMode, parse_execution_mode
from src.orchestration.phases import ScanPhase
from src.quick.disallowed import NOT_SCHEDULED_BY_QUICK_PROFILE
from src.quick.planner import plan_for_va_target
from src.quick.schemas import QuickScanPlan, QuickTask, QuickTaskStage

STAGE_ORDER: tuple[str, ...] = (
    QuickTaskStage.DISCOVERY.value,
    QuickTaskStage.FINGERPRINT.value,
    QuickTaskStage.TEST.value,
    QuickTaskStage.VERIFY.value,
    QuickTaskStage.TRIAGE.value,
    QuickTaskStage.REPORT.value,
)

QUICK_PHASE_ALLOWLIST: frozenset[ScanPhase] = frozenset(
    {
        ScanPhase.RECON,
        ScanPhase.THREAT_MODELING,
        ScanPhase.VULN_ANALYSIS,
        ScanPhase.REPORTING,
    }
)

SKIPPED_BY_QUICK_PROFILE: frozenset[ScanPhase] = frozenset(
    {
        ScanPhase.SOURCE_ANALYSIS,
        ScanPhase.QUICK_FUZZ,
        ScanPhase.EXPLOITATION,
        ScanPhase.POST_EXPLOITATION,
    }
)

DISCOVERY_PHASES: frozenset[ScanPhase] = frozenset(
    {
        ScanPhase.SOURCE_ANALYSIS,
        ScanPhase.RECON,
        ScanPhase.QUICK_FUZZ,
        ScanPhase.THREAT_MODELING,
    }
)

VERIFICATION_AND_REPORT_PHASES: frozenset[ScanPhase] = frozenset(
    {
        ScanPhase.VULN_ANALYSIS,
        ScanPhase.REPORTING,
    }
)

DISCOVERY_STAGES: frozenset[str] = frozenset(
    {
        QuickTaskStage.DISCOVERY.value,
        QuickTaskStage.FINGERPRINT.value,
    }
)

PROTECTED_STAGES: frozenset[str] = frozenset(
    {
        QuickTaskStage.VERIFY.value,
        QuickTaskStage.TRIAGE.value,
        QuickTaskStage.REPORT.value,
    }
)

PHASE_SKIP_REASONS: dict[ScanPhase, str] = {
    ScanPhase.SOURCE_ANALYSIS: NOT_SCHEDULED_BY_QUICK_PROFILE,
    ScanPhase.QUICK_FUZZ: NOT_SCHEDULED_BY_QUICK_PROFILE,
    ScanPhase.EXPLOITATION: NOT_SCHEDULED_BY_QUICK_PROFILE,
    ScanPhase.POST_EXPLOITATION: NOT_SCHEDULED_BY_QUICK_PROFILE,
}

_STAGE_RANK: dict[str, int] = {name: index for index, name in enumerate(STAGE_ORDER)}


class CyclicQuickWorkflowError(ValueError):
    code = "cyclic_quick_workflow"

    def __init__(self, message: str = "cyclic_quick_workflow") -> None:
        super().__init__(message)


def is_quick_execution(options: Mapping[str, Any] | None) -> bool:
    opts = options if isinstance(options, Mapping) else {}
    raw = opts.get("execution_mode")
    if raw is None:
        ctx = opts.get("execution_mode_context")
        if isinstance(ctx, Mapping):
            raw = ctx.get("mode")
    try:
        return parse_execution_mode(raw if isinstance(raw, str) else None) is ExecutionMode.QUICK
    except ValueError:
        return False


def skipped_phases_for_options(options: Mapping[str, Any] | None) -> frozenset[ScanPhase]:
    if is_quick_execution(options):
        return SKIPPED_BY_QUICK_PROFILE
    return frozenset()


def phase_allowed(phase: ScanPhase, options: Mapping[str, Any] | None) -> bool:
    if not is_quick_execution(options):
        return True
    return phase in QUICK_PHASE_ALLOWLIST


def skip_reason_for_phase(phase: ScanPhase) -> str:
    return PHASE_SKIP_REASONS.get(phase, NOT_SCHEDULED_BY_QUICK_PROFILE)


def skipped_phase_payload(phase: ScanPhase, reason: str | None = None) -> dict[str, Any]:
    code = reason or skip_reason_for_phase(phase)
    return {
        "skipped": True,
        "skip_reason": code,
        "coverage_reason": code,
        "coverage_reason_code": code,
        "phase": phase.value,
    }


def resolve_quick_plan(
    *,
    scan_id: str,
    target: str,
    options: Mapping[str, Any] | None,
) -> QuickScanPlan | None:
    """Return a stored plan from options, or build a deterministic VA plan."""
    if not is_quick_execution(options):
        return None
    opts = dict(options or {})
    stored = opts.get("quick_plan")
    if isinstance(stored, QuickScanPlan):
        return stored
    if isinstance(stored, Mapping):
        try:
            return QuickScanPlan.model_validate(stored)
        except ValidationError:
            stored = None
    if not target:
        return None
    opts.setdefault("scan_id", scan_id)
    return plan_for_va_target(target_url=target, scan_options=opts)


class QuickWorkflow:
    """DAG over ``QuickTask.depends_on`` with stable stage order."""

    def __init__(self, tasks: Sequence[QuickTask]) -> None:
        self._tasks: dict[str, QuickTask] = {task.task_id: task for task in tasks}
        self._validate()

    @classmethod
    def from_plan(cls, plan: QuickScanPlan) -> QuickWorkflow:
        return cls(plan.tasks)

    def _validate(self) -> None:
        known = set(self._tasks)
        for task in self._tasks.values():
            for dep in task.depends_on:
                if dep not in known:
                    raise ValueError(f"unknown_quick_dependency:{dep}")
        self._assert_acyclic()

    def _assert_acyclic(self) -> None:
        incoming: dict[str, int] = dict.fromkeys(self._tasks, 0)
        adjacency: dict[str, list[str]] = defaultdict(list)
        for task in self._tasks.values():
            for dep in task.depends_on:
                adjacency[dep].append(task.task_id)
                incoming[task.task_id] += 1
        queue: deque[str] = deque(
            task_id for task_id, count in incoming.items() if count == 0
        )
        seen = 0
        while queue:
            node = queue.popleft()
            seen += 1
            for child in adjacency[node]:
                incoming[child] -= 1
                if incoming[child] == 0:
                    queue.append(child)
        if seen != len(self._tasks):
            raise CyclicQuickWorkflowError()

    def tasks(self) -> tuple[QuickTask, ...]:
        return tuple(self._tasks[task_id] for task_id in self._ordered_ids())

    def ready_tasks(
        self,
        completed_ids: set[str],
        *,
        blocked_ids: set[str] | None = None,
    ) -> tuple[QuickTask, ...]:
        """Tasks whose dependencies succeeded and that are not blocked/completed."""
        blocked = blocked_ids or set()
        ready: list[QuickTask] = []
        for task in self.tasks():
            if task.task_id in completed_ids or task.task_id in blocked:
                continue
            if any(dep not in completed_ids for dep in task.depends_on):
                continue
            ready.append(task)
        return tuple(ready)

    def _ordered_ids(self) -> list[str]:
        return sorted(
            self._tasks,
            key=lambda task_id: (
                _STAGE_RANK.get(self._tasks[task_id].stage.value, 99),
                -self._tasks[task_id].priority_score,
                self._tasks[task_id].capability_id,
                self._tasks[task_id].tool_id,
                task_id,
            ),
        )


__all__ = [
    "DISCOVERY_PHASES",
    "DISCOVERY_STAGES",
    "PHASE_SKIP_REASONS",
    "PROTECTED_STAGES",
    "QUICK_PHASE_ALLOWLIST",
    "SKIPPED_BY_QUICK_PROFILE",
    "STAGE_ORDER",
    "VERIFICATION_AND_REPORT_PHASES",
    "CyclicQuickWorkflowError",
    "QuickWorkflow",
    "is_quick_execution",
    "phase_allowed",
    "resolve_quick_plan",
    "skip_reason_for_phase",
    "skipped_phase_payload",
    "skipped_phases_for_options",
]
