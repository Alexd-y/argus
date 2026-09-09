"""Concrete test executions + deterministic aggregation (ARGUS-WSTG-COV-1 §Execution).

A :class:`TestExecution` records *what was actually run* for one WSTG
test/scenario, produced by a real parser/producer (see ``wstg_producers``). The
handler that builds an execution is responsible for setting:

* what was actually checked (``completion_criteria_results``);
* whether the mandatory steps ran (``execution_status``);
* whether the outcome is determined (``outcome``);
* which artifacts back it (``evidence_refs``).

Never infer ``completed`` from a tool name or a zero process exit code, and never
infer ``pass`` from the absence of findings.

:func:`aggregate_executions` reduces many executions (including repeats and
conflicts) into one deterministic per-test verdict:

* repeated executions of the *same* scenario collapse to the strongest outcome
  (``fail > pass > inconclusive > not_evaluated``) — a repeat never inflates the
  numerator;
* a later empty ``pass`` never erases an earlier confirmed ``fail``;
* a test is ``completed`` only when every required scenario reached a determined
  terminal result;
* a genuine fail/pass contradiction on the same scenario sets ``conflict``.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.reports.wstg_model import ExecutionStatus, Outcome

_OUTCOME_RANK: dict[Outcome, int] = {
    Outcome.NOT_EVALUATED: 0,
    Outcome.INCONCLUSIVE: 1,
    Outcome.PASS: 2,
    Outcome.FAIL: 3,
}

_TERMINAL_STATUSES = frozenset(
    {ExecutionStatus.COMPLETED, ExecutionStatus.FAILED, ExecutionStatus.BLOCKED}
)


@dataclass(frozen=True)
class TestExecution:
    """One concrete execution of a WSTG test/scenario."""

    # Not a pytest test class despite the ``Test`` prefix.
    __test__ = False

    execution_id: str
    scan_id: str
    test_id: str
    scenario_id: str | None
    executor: str
    executor_version: str | None = None
    target_ref: str | None = None
    actor_context_ref: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    execution_status: ExecutionStatus = ExecutionStatus.NOT_STARTED
    outcome: Outcome = Outcome.NOT_EVALUATED
    evidence_refs: tuple[str, ...] = ()
    completion_criteria_results: dict[str, bool] = field(default_factory=dict)
    limitations: tuple[str, ...] = ()
    error_code: str | None = None

    def required_criteria_met(self) -> bool:
        """All declared completion criteria were satisfied (empty → not met)."""
        return bool(self.completion_criteria_results) and all(
            self.completion_criteria_results.values()
        )


@dataclass
class AggregatedTest:
    """Deterministic per-test aggregate of its executions."""

    test_id: str
    execution_status: ExecutionStatus
    outcome: Outcome
    evidence_refs: list[str]
    scenario_ids: list[str]
    required_scenarios_completed: bool
    conflict: bool
    limitations: list[str] = field(default_factory=list)


def _sort_key(e: TestExecution) -> tuple:
    return (_OUTCOME_RANK[e.outcome], e.finished_at or "", e.execution_id)


def _reduce_scenario(execs: list[TestExecution]) -> tuple[TestExecution, bool]:
    """Collapse repeats of one scenario; detect a pass/fail conflict."""
    strongest = max(execs, key=_sort_key)
    outcomes = {e.outcome for e in execs}
    conflict = Outcome.FAIL in outcomes and Outcome.PASS in outcomes
    return strongest, conflict


def aggregate_executions(
    executions: list[TestExecution],
    *,
    required_scenarios: dict[str, set[str]] | None = None,
) -> dict[str, AggregatedTest]:
    """Aggregate raw executions into one verdict per ``test_id``.

    ``required_scenarios`` maps ``test_id`` → the set of scenario ids that must
    complete for the test to be ``completed``. When omitted, every observed
    scenario for a test is treated as required.
    """
    by_test: dict[str, list[TestExecution]] = {}
    for e in executions:
        by_test.setdefault(e.test_id, []).append(e)

    required = required_scenarios or {}
    out: dict[str, AggregatedTest] = {}

    for test_id, execs in by_test.items():
        # Group by scenario (None → a synthetic single-scenario bucket).
        by_scenario: dict[str, list[TestExecution]] = {}
        for e in execs:
            by_scenario.setdefault(e.scenario_id or f"__test__:{test_id}", []).append(e)

        scenario_reduced: dict[str, TestExecution] = {}
        conflict = False
        for sid, sexecs in by_scenario.items():
            strongest, sconflict = _reduce_scenario(sexecs)
            scenario_reduced[sid] = strongest
            conflict = conflict or sconflict

        # Aggregate outcome: strongest across scenarios (fail dominates).
        agg_outcome = max(
            (e.outcome for e in scenario_reduced.values()),
            key=lambda o: _OUTCOME_RANK[o],
            default=Outcome.NOT_EVALUATED,
        )

        # Required-scenario completion.
        req = required.get(test_id) or set(scenario_reduced)
        completed_scenarios = {
            sid
            for sid, e in scenario_reduced.items()
            if e.execution_status == ExecutionStatus.COMPLETED and e.required_criteria_met()
        }
        required_completed = bool(req) and req.issubset(completed_scenarios)

        # Overall execution status.
        statuses = {e.execution_status for e in scenario_reduced.values()}
        if required_completed:
            exec_status = ExecutionStatus.COMPLETED
        elif ExecutionStatus.RUNNING in statuses:
            exec_status = ExecutionStatus.RUNNING
        elif completed_scenarios or ExecutionStatus.PARTIAL in statuses:
            exec_status = ExecutionStatus.PARTIAL
        elif statuses <= _TERMINAL_STATUSES and ExecutionStatus.FAILED in statuses:
            exec_status = ExecutionStatus.FAILED
        elif ExecutionStatus.BLOCKED in statuses:
            exec_status = ExecutionStatus.BLOCKED
        else:
            exec_status = ExecutionStatus.NOT_STARTED

        evidence: list[str] = []
        for e in scenario_reduced.values():
            for ref in e.evidence_refs:
                if ref not in evidence:
                    evidence.append(ref)

        limitations: list[str] = []
        for e in scenario_reduced.values():
            for lim in e.limitations:
                if lim not in limitations:
                    limitations.append(lim)

        out[test_id] = AggregatedTest(
            test_id=test_id,
            execution_status=exec_status,
            outcome=agg_outcome,
            evidence_refs=evidence,
            scenario_ids=sorted(s for s in by_scenario if not s.startswith("__test__:")),
            required_scenarios_completed=required_completed,
            conflict=conflict,
            limitations=limitations,
        )
    return out


__all__ = ["AggregatedTest", "TestExecution", "aggregate_executions"]
