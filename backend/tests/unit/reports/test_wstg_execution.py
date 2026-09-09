"""ARGUS-WSTG-COV-1 — execution aggregation tests (spec §14 scenarios 8, 16)."""

from __future__ import annotations

from src.reports.wstg_execution import TestExecution, aggregate_executions
from src.reports.wstg_model import ExecutionStatus, Outcome


def _exec(
    execution_id: str,
    test_id: str,
    *,
    scenario_id: str | None = "s1",
    status: ExecutionStatus = ExecutionStatus.COMPLETED,
    outcome: Outcome = Outcome.PASS,
    evidence=("ev",),
    finished_at: str = "2026-01-01T00:00:00Z",
    criteria: dict[str, bool] | None = None,
) -> TestExecution:
    return TestExecution(
        execution_id=execution_id,
        scan_id="scan-1",
        test_id=test_id,
        scenario_id=scenario_id,
        executor="producer",
        execution_status=status,
        outcome=outcome,
        evidence_refs=tuple(evidence),
        finished_at=finished_at,
        completion_criteria_results=criteria if criteria is not None else {"c1": True},
    )


def test_single_completed_execution_aggregates_to_completed():
    agg = aggregate_executions([_exec("e1", "A")])
    a = agg["A"]
    assert a.execution_status == ExecutionStatus.COMPLETED
    assert a.outcome == Outcome.PASS
    assert a.required_scenarios_completed is True


def test_scenario16_repeat_does_not_inflate_and_keeps_single_test():
    execs = [_exec("e1", "A"), _exec("e2", "A"), _exec("e3", "A")]
    agg = aggregate_executions(execs)
    assert set(agg) == {"A"}
    assert agg["A"].scenario_ids == ["s1"]


def test_later_empty_pass_does_not_erase_confirmed_fail():
    fail = _exec("e1", "A", outcome=Outcome.FAIL, finished_at="2026-01-01T00:00:00Z")
    later_pass = _exec("e2", "A", outcome=Outcome.PASS, finished_at="2026-02-01T00:00:00Z")
    agg = aggregate_executions([fail, later_pass])
    assert agg["A"].outcome == Outcome.FAIL
    assert agg["A"].conflict is True


def test_incomplete_criteria_blocks_completed():
    agg = aggregate_executions([_exec("e1", "A", criteria={"c1": False})])
    assert agg["A"].required_scenarios_completed is False
    assert agg["A"].execution_status != ExecutionStatus.COMPLETED


def test_multiple_required_scenarios_partial_when_one_missing():
    e1 = _exec("e1", "A", scenario_id="s1")
    e2 = _exec("e2", "A", scenario_id="s2", status=ExecutionStatus.PARTIAL, criteria={"c": False})
    agg = aggregate_executions([e1, e2], required_scenarios={"A": {"s1", "s2"}})
    assert agg["A"].required_scenarios_completed is False
    assert agg["A"].execution_status == ExecutionStatus.PARTIAL


def test_empty_criteria_never_counts_as_completed():
    agg = aggregate_executions([_exec("e1", "A", criteria={})])
    assert agg["A"].required_scenarios_completed is False
