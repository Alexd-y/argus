"""Deadline-aware Quick scheduler.

Stops new discovery near the wall-clock deadline, keeps verification and
report, and respects per-host concurrency, circuit breaker, and idempotency.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum
from typing import Any

from src.quick.audit import emit_quick_audit_event
from src.quick.budget import (
    QuickBudgetManager,
    normalize_host_key,
)
from src.quick.circuit_breaker import (
    CIRCUIT_OPEN_REASON,
    QuickCircuitBreaker,
    default_circuit_breaker,
)
from src.quick.clock import Clock, SystemClock, as_utc
from src.quick.idempotency import (
    IdempotencyClaim,
    QuickIdempotencyStore,
    default_idempotency_store,
)
from src.quick.metrics import record_deadline_overrun, record_task
from src.quick.schemas import QuickTask
from src.quick.workflow import (
    DISCOVERY_STAGES,
    PROTECTED_STAGES,
    QuickWorkflow,
)

logger = logging.getLogger(__name__)

_DEFAULT_PER_HOST_RUNNING = 1


class ScheduleSkipReason(StrEnum):
    CANCELLED = "cancelled"
    DEADLINE_REACHED = "deadline_reached"
    STOP_DISCOVERY = "stop_discovery"
    CIRCUIT_OPEN = CIRCUIT_OPEN_REASON
    IDEMPOTENT = "idempotent_hit"
    CONCURRENCY = "concurrency_limit"
    NO_READY = "no_ready_tasks"


class SchedulePick:
    """Result of one scheduler tick. ``task`` is None when nothing should start."""

    __slots__ = ("skip_reason", "skipped_task_ids", "task")

    def __init__(
        self,
        task: QuickTask | None,
        *,
        skip_reason: ScheduleSkipReason | None = None,
        skipped_task_ids: tuple[str, ...] = (),
    ) -> None:
        self.task = task
        self.skip_reason = skip_reason
        self.skipped_task_ids = skipped_task_ids


_BUDGET_MANAGER: QuickBudgetManager | None = None


def get_quick_budget_manager() -> QuickBudgetManager:
    global _BUDGET_MANAGER
    if _BUDGET_MANAGER is None:
        _BUDGET_MANAGER = QuickBudgetManager()
    return _BUDGET_MANAGER


def seconds_until_deadline(deadline_at: datetime | None, clock: Clock | None = None) -> float:
    if deadline_at is None:
        return float("inf")
    source = clock if clock is not None else SystemClock()
    remaining = (as_utc(deadline_at) - as_utc(source.now())).total_seconds()
    return max(0.0, remaining)


def quick_deadline_reached(scan_id: str, options: Mapping[str, Any] | None) -> bool:
    manager = get_quick_budget_manager()
    if manager.is_open(scan_id):
        return manager.deadline_reached(scan_id)
    deadline = deadline_from_options(options)
    if deadline is None:
        return False
    return seconds_until_deadline(deadline) <= 0


def quick_should_stop_discovery(scan_id: str, options: Mapping[str, Any] | None) -> bool:
    manager = get_quick_budget_manager()
    if manager.is_open(scan_id):
        return manager.should_stop_discovery(scan_id)
    return quick_deadline_reached(scan_id, options)


def deadline_from_options(options: Mapping[str, Any] | None) -> datetime | None:
    opts = options if isinstance(options, Mapping) else {}
    raw = opts.get("deadline_at")
    if isinstance(raw, datetime):
        return as_utc(raw)
    if isinstance(raw, str) and raw.strip():
        try:
            parsed = datetime.fromisoformat(raw)
        except ValueError:
            return None
        return as_utc(parsed)
    return None


class QuickScheduler:
    """Pick the next runnable Quick task under budget, fairness, and cancel constraints."""

    def __init__(
        self,
        workflow: QuickWorkflow,
        *,
        budget_manager: QuickBudgetManager | None = None,
        circuit_breaker: QuickCircuitBreaker | None = None,
        idempotency: QuickIdempotencyStore | None = None,
        clock: Clock | None = None,
        per_host_running_limit: int = _DEFAULT_PER_HOST_RUNNING,
        plan_version: int = 1,
    ) -> None:
        self._workflow = workflow
        self._budget = budget_manager if budget_manager is not None else get_quick_budget_manager()
        self._breaker = circuit_breaker if circuit_breaker is not None else default_circuit_breaker()
        self._idempotency = (
            idempotency if idempotency is not None else default_idempotency_store()
        )
        self._clock: Clock = clock if clock is not None else SystemClock()
        self._per_host_limit = max(1, per_host_running_limit)
        self._plan_version = max(1, plan_version)

    def _deadline_flags(self, scan_id: str) -> tuple[bool, bool]:
        if not self._budget.is_open(scan_id):
            return False, False
        return self._budget.deadline_reached(scan_id), self._budget.should_stop_discovery(scan_id)

    def _gate_reason(
        self,
        task: QuickTask,
        *,
        scan_id: str,
        stop_discovery: bool,
        hosts: Mapping[str, int],
        lease_remaining: bool,
    ) -> ScheduleSkipReason | None:
        if stop_discovery and task.stage.value in DISCOVERY_STAGES:
            return ScheduleSkipReason.STOP_DISCOVERY
        host = normalize_host_key(task.target_ref)
        if self._breaker.is_open(task.tool_id, host):
            logger.info(
                "quick_scheduler_circuit_skip",
                extra={
                    "event": "quick_scheduler_circuit_skip",
                    "scan_id": scan_id,
                    "tool_id": task.tool_id,
                    "coverage_reason": CIRCUIT_OPEN_REASON,
                },
            )
            return ScheduleSkipReason.CIRCUIT_OPEN
        record = self._idempotency.get(task.idempotency_key)
        if record is not None:
            if record.status == "succeeded":
                return ScheduleSkipReason.IDEMPOTENT
            if record.status == "running":
                return ScheduleSkipReason.IDEMPOTENT
            if record.status in {"failed", "timed_out", "lost"} and not lease_remaining:
                return ScheduleSkipReason.IDEMPOTENT
        if hosts.get(host, 0) >= self._per_host_limit:
            return ScheduleSkipReason.CONCURRENCY
        return None

    def eligible_tasks(
        self,
        *,
        scan_id: str,
        completed_ids: set[str],
        running_ids: set[str] | None = None,
        running_hosts: Mapping[str, int] | None = None,
        cancelled: bool = False,
        lease_remaining: bool = True,
    ) -> tuple[QuickTask, ...]:
        """Ready tasks that may start now. Does not claim idempotency keys."""
        if cancelled:
            return ()
        deadline, stop_discovery = self._deadline_flags(scan_id)
        blocked = running_ids or set()
        hosts = dict(running_hosts or {})
        selected: list[QuickTask] = []
        for task in self._workflow.ready_tasks(completed_ids, blocked_ids=blocked):
            if deadline and task.stage.value not in PROTECTED_STAGES:
                continue
            reason = self._gate_reason(
                task,
                scan_id=scan_id,
                stop_discovery=stop_discovery,
                hosts=hosts,
                lease_remaining=lease_remaining,
            )
            if reason is not None:
                continue
            selected.append(task)
        return tuple(selected)

    def pick_next(
        self,
        *,
        scan_id: str,
        completed_ids: set[str],
        running_ids: set[str],
        running_hosts: Mapping[str, int] | None = None,
        cancelled: bool = False,
        lease_remaining: bool = True,
    ) -> SchedulePick:
        if cancelled:
            return SchedulePick(None, skip_reason=ScheduleSkipReason.CANCELLED)
        deadline, stop_discovery = self._deadline_flags(scan_id)
        if deadline:
            protected = self._ready_protected(completed_ids, running_ids)
            if protected is None:
                record_deadline_overrun()
                return SchedulePick(None, skip_reason=ScheduleSkipReason.DEADLINE_REACHED)
            record_task(
                stage=protected.stage.value,
                status=protected.status.value,
                tool=protected.tool_id,
            )
            return SchedulePick(protected, skip_reason=ScheduleSkipReason.DEADLINE_REACHED)

        skipped: list[str] = []
        hosts = dict(running_hosts or {})
        for task in self._workflow.ready_tasks(completed_ids, blocked_ids=running_ids):
            reason = self._gate_reason(
                task,
                scan_id=scan_id,
                stop_discovery=stop_discovery,
                hosts=hosts,
                lease_remaining=lease_remaining,
            )
            if reason is ScheduleSkipReason.CONCURRENCY:
                continue
            if reason is not None:
                skipped.append(task.task_id)
                continue
            claim = self._idempotency.claim(
                task.idempotency_key,
                scan_id=scan_id,
                tool_id=task.tool_id,
                plan_version=self._plan_version,
                lease_remaining=lease_remaining,
            )
            if claim is IdempotencyClaim.DUPLICATE_SUCCEEDED:
                skipped.append(task.task_id)
                continue
            if claim is IdempotencyClaim.IN_FLIGHT:
                continue
            if claim is IdempotencyClaim.BLOCKED:
                skipped.append(task.task_id)
                continue
            record_task(stage=task.stage.value, status="leased", tool=task.tool_id)
            emit_quick_audit_event(
                "quick.tool",
                scan_id=scan_id,
                payload={"tool_id": task.tool_id, "task_id": task.task_id, "stage": task.stage.value},
            )
            return SchedulePick(task, skipped_task_ids=tuple(skipped))

        reason = (
            ScheduleSkipReason.STOP_DISCOVERY
            if stop_discovery and skipped
            else ScheduleSkipReason.NO_READY
        )
        if any(
            self._breaker.is_open(task.tool_id, normalize_host_key(task.target_ref))
            for task in self._workflow.tasks()
            if task.task_id not in completed_ids
        ):
            reason = ScheduleSkipReason.CIRCUIT_OPEN
        return SchedulePick(None, skip_reason=reason, skipped_task_ids=tuple(skipped))

    def _ready_protected(
        self,
        completed_ids: set[str],
        running_ids: set[str],
    ) -> QuickTask | None:
        for task in self._workflow.ready_tasks(completed_ids, blocked_ids=running_ids):
            if task.stage.value in PROTECTED_STAGES:
                return task
        return None


__all__ = [
    "QuickScheduler",
    "SchedulePick",
    "ScheduleSkipReason",
    "deadline_from_options",
    "get_quick_budget_manager",
    "quick_deadline_reached",
    "quick_should_stop_discovery",
    "seconds_until_deadline",
]
