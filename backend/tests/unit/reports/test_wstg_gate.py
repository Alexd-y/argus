"""Track B §4/§12 — strict, evidence-based WSTG coverage gate regression tests."""

from __future__ import annotations

from src.reports.wstg_gate import (
    ExecutionStatus,
    WstgTestState,
    compute_wstg_coverage,
)
from src.reports.wstg_gate import TestResult as Res


def _completed(test_id: str, result: Res = Res.PASS, evidence=("e1",)) -> WstgTestState:
    return WstgTestState(
        test_id=test_id,
        execution_status=ExecutionStatus.COMPLETED,
        result=result,
        evidence_ids=list(evidence),
    )


def test_completed_pass_and_fail_both_count():
    states = [_completed("A", Res.PASS), _completed("B", Res.FAIL)]
    rep = compute_wstg_coverage(states)
    assert rep.counted == 2
    assert rep.coverage_pct == 100.0


def test_partial_does_not_count_as_half():
    states = [
        _completed("A"),
        WstgTestState("B", ExecutionStatus.PARTIAL, Res.NOT_EVALUATED, ["e"]),
    ]
    rep = compute_wstg_coverage(states)
    assert rep.counted == 1
    assert rep.partial == 1
    assert rep.coverage_pct == 50.0  # 1/2, NOT 1.5/2


def test_blocked_failed_notstarted_running_are_zero():
    states = [
        _completed("A"),
        WstgTestState("B", ExecutionStatus.BLOCKED),
        WstgTestState("C", ExecutionStatus.FAILED),
        WstgTestState("D", ExecutionStatus.NOT_STARTED),
        WstgTestState("E", ExecutionStatus.RUNNING),
    ]
    rep = compute_wstg_coverage(states)
    assert rep.counted == 1
    assert rep.coverage_pct == 20.0


def test_inconclusive_result_does_not_count():
    states = [_completed("A"), _completed("B", Res.INCONCLUSIVE)]
    rep = compute_wstg_coverage(states)
    assert rep.counted == 1
    assert rep.inconclusive == 1


def test_missing_evidence_blocks_completed():
    states = [_completed("A"), _completed("B", Res.PASS, evidence=())]
    rep = compute_wstg_coverage(states)
    assert rep.counted == 1


def test_exactly_80_percent_fails_gate():
    # 8 counted out of 10 applicable = exactly 80.0 → gate must NOT pass.
    states = [_completed(f"C{i}") for i in range(8)]
    states += [WstgTestState(f"N{i}", ExecutionStatus.NOT_STARTED) for i in range(2)]
    rep = compute_wstg_coverage(states)
    assert rep.coverage_pct == 80.0
    assert rep.gate_passed is False


def test_above_80_percent_passes_gate():
    # 9 / 10 = 90% → passes.
    states = [_completed(f"C{i}") for i in range(9)]
    states += [WstgTestState("N0", ExecutionStatus.NOT_STARTED)]
    rep = compute_wstg_coverage(states)
    assert rep.coverage_pct == 90.0
    assert rep.gate_passed is True


def test_not_applicable_with_rationale_excluded_from_denominator():
    states = [
        _completed("A"),
        WstgTestState("B", ExecutionStatus.NOT_APPLICABLE, exclusion_rationale="no SOAP surface"),
    ]
    rep = compute_wstg_coverage(states)
    assert rep.applicable == 1
    assert rep.not_applicable == 1
    assert rep.coverage_pct == 100.0  # 1 counted / 1 applicable
    assert rep.exclusion_errors == []


def test_not_applicable_without_rationale_stays_applicable_and_errors():
    states = [
        _completed("A"),
        WstgTestState("B", ExecutionStatus.NOT_APPLICABLE),  # no rationale
    ]
    rep = compute_wstg_coverage(states)
    # Fail-closed: B remains in the denominator; coverage 1/2, gate cannot pass.
    assert rep.applicable == 2
    assert rep.coverage_pct == 50.0
    assert rep.exclusion_errors and "B" in rep.exclusion_errors[0]


def test_unjustified_exclusion_blocks_gate_even_above_threshold():
    states = [_completed(f"C{i}") for i in range(9)]
    states.append(WstgTestState("X", ExecutionStatus.NOT_APPLICABLE))  # unjustified
    rep = compute_wstg_coverage(states)
    # X stays applicable (fail-closed): 9 counted / 10 applicable = 90%.
    assert rep.coverage_pct == 90.0
    assert rep.gate_passed is False  # blocked by unjustified exclusion
    assert rep.exclusion_errors


def test_completed_of_catalog_ratio_exposes_true_effort():
    states = [_completed("A")]
    rep = compute_wstg_coverage(states, catalog_size=96)
    assert rep.coverage_pct == 100.0  # 1/1 applicable in this scope
    assert round(rep.completed_of_catalog_pct, 2) == round(1 / 96 * 100, 2)


def test_empty_states_is_zero_not_crash():
    rep = compute_wstg_coverage([])
    assert rep.counted == 0
    assert rep.coverage_pct == 0.0
    assert rep.gate_passed is False
