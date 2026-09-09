"""ARGUS-WSTG-COV-1 — deterministic coverage gate math + integrity tests.

These replace the legacy "any reduced toolset must reach >80%" assertions with
fact-based classification checks (spec §14 scenarios 17-25).
"""

from __future__ import annotations

from src.reports.wstg_gate import (
    Applicability,
    AssessmentStatus,
    ExecutionStatus,
    IntegrityCode,
    Outcome,
    Scope,
    WstgTestState,
    compute_wstg_coverage,
)


def _completed(test_id: str, outcome: Outcome = Outcome.PASS, *, evidence=True) -> WstgTestState:
    return WstgTestState(
        test_id=test_id,
        execution_status=ExecutionStatus.COMPLETED,
        outcome=outcome,
        evidence_refs=["ev-1"] if evidence else [],
        evidence_validated=evidence,
        completion_criteria_met=True,
    )


def _valid_na(test_id: str) -> WstgTestState:
    return WstgTestState(
        test_id=test_id,
        applicability=Applicability.NOT_APPLICABLE,
        applicability_valid=True,
        rationale="feature confirmed absent in scope",
        evidence_refs=["ev-na"],
    )


def test_completed_pass_and_fail_both_count():
    rep = compute_wstg_coverage([_completed("A", Outcome.PASS), _completed("B", Outcome.FAIL)])
    assert rep.counted == 2
    assert rep.coverage_pct == 100.0
    assert rep.assessment_status == AssessmentStatus.COMPLETE


def test_partial_does_not_count_as_half():
    states = [
        _completed("A"),
        WstgTestState("B", execution_status=ExecutionStatus.PARTIAL),
    ]
    rep = compute_wstg_coverage(states)
    assert rep.counted == 1
    assert rep.partial == 1
    assert rep.coverage_pct == 50.0


def test_scenario8_tool_name_alone_is_not_completed():
    # A state built only from a tool run (no evidence, not completed) never counts.
    states = [WstgTestState("A", execution_status=ExecutionStatus.RUNNING)]
    rep = compute_wstg_coverage(states)
    assert rep.counted == 0
    assert rep.coverage_pct == 0.0


def test_scenario9_static_evidence_id_without_artifact_not_counted():
    # evidence_validated=False → does not count and is flagged.
    states = [_completed("A", evidence=False)]
    rep = compute_wstg_coverage(states)
    assert rep.counted == 0
    assert any(e.code == IntegrityCode.COMPLETED_WITHOUT_EVIDENCE for e in rep.integrity_errors)


def test_scenario12_no_findings_is_not_automatic_pass():
    # A test that only ran a tool with no determined outcome stays uncounted.
    states = [
        WstgTestState(
            "A",
            execution_status=ExecutionStatus.COMPLETED,
            outcome=Outcome.NOT_EVALUATED,
            evidence_validated=True,
            completion_criteria_met=True,
        )
    ]
    rep = compute_wstg_coverage(states)
    assert rep.counted == 0


def test_scenario13_valid_scenario_result_can_pass():
    rep = compute_wstg_coverage([_completed("A", Outcome.PASS)])
    assert rep.counted == 1
    assert rep.coverage_pct == 100.0


def test_scenario14_confirmed_fail_on_incomplete_test_is_kept_uncounted():
    # A confirmed fail with incomplete criteria is a security result, but the
    # test is not counted as fully completed.
    states = [
        _completed("A"),
        WstgTestState(
            "B",
            execution_status=ExecutionStatus.PARTIAL,
            outcome=Outcome.FAIL,
            evidence_refs=["e"],
            evidence_validated=True,
            completion_criteria_met=False,
        ),
    ]
    rep = compute_wstg_coverage(states)
    assert rep.counted == 1  # only A
    assert rep.completed_fail == 0  # B is partial, not completed
    assert rep.coverage_pct == 50.0


def test_scenario17_applicable_false_without_decision_detected_any_status():
    # not_applicable without a valid decision, regardless of execution status.
    bad = WstgTestState(
        "B",
        applicability=Applicability.NOT_APPLICABLE,
        applicability_valid=False,
        execution_status=ExecutionStatus.RUNNING,
    )
    rep = compute_wstg_coverage([_completed("A"), bad])
    assert any(e.code == IntegrityCode.UNJUSTIFIED_EXCLUSION for e in rep.integrity_errors)
    assert rep.evidence_integrity_passed is False
    assert rep.assessment_status == AssessmentStatus.INVALID


def test_scenario18_blank_rationale_rejected():
    bad = WstgTestState(
        "B",
        applicability=Applicability.NOT_APPLICABLE,
        applicability_valid=True,
        rationale="   ",
    )
    rep = compute_wstg_coverage([_completed("A"), bad])
    assert any(e.code == IntegrityCode.BLANK_RATIONALE for e in rep.integrity_errors)


def test_scenario19_missing_catalog_row_does_not_shrink_denominator():
    catalog = frozenset({"A", "B", "C"})
    # Only A and B supplied; C missing must be flagged, not silently dropped.
    rep = compute_wstg_coverage([_completed("A"), _completed("B")], catalog_ids=catalog)
    assert rep.catalog_total == 3
    assert any(e.code == IntegrityCode.MISSING_CATALOG_TEST for e in rep.integrity_errors)
    assert rep.coverage_pct is None  # integrity violation → undefined


def test_scenario20_duplicate_and_unknown_ids_detected():
    catalog = frozenset({"A"})
    states = [_completed("A"), _completed("A"), _completed("Z")]
    rep = compute_wstg_coverage(states, catalog_ids=catalog)
    codes = {e.code for e in rep.integrity_errors}
    assert IntegrityCode.DUPLICATE_TEST_ID in codes
    assert IntegrityCode.UNKNOWN_TEST_ID in codes


def test_scenario21_zero_denominator_fails_gate_with_null():
    rep = compute_wstg_coverage([_valid_na("A")])
    assert rep.denominator == 0
    assert rep.coverage_pct is None
    assert rep.coverage_gate_passed is False


def test_scenario22_exactly_80_percent_fails():
    states = [_completed(f"C{i}") for i in range(8)]
    states += [
        WstgTestState(f"N{i}", execution_status=ExecutionStatus.NOT_STARTED) for i in range(2)
    ]
    rep = compute_wstg_coverage(states)
    assert rep.coverage_pct == 80.0
    assert rep.coverage_gate_passed is False
    assert rep.assessment_status == AssessmentStatus.INCOMPLETE


def test_scenario23_rounding_does_not_change_decision():
    # 8/9 = 88.88.. > 80 passes on the unrounded value.
    states = [_completed(f"C{i}") for i in range(8)]
    states += [WstgTestState("N0", execution_status=ExecutionStatus.NOT_STARTED)]
    rep = compute_wstg_coverage(states)
    assert rep.coverage_pct is not None and rep.coverage_pct > 80.0
    assert rep.coverage_gate_passed is True


def test_valid_na_excluded_from_denominator():
    rep = compute_wstg_coverage([_completed("A"), _valid_na("B")])
    assert rep.denominator == 1
    assert rep.validated_not_applicable == 1
    assert rep.coverage_pct == 100.0


def test_na_contradicted_by_finding_is_integrity_error():
    contradicted = WstgTestState(
        "B",
        applicability=Applicability.NOT_APPLICABLE,
        applicability_valid=True,
        rationale="claimed absent",
        evidence_refs=["e"],
        outcome=Outcome.FAIL,
    )
    rep = compute_wstg_coverage([_completed("A"), contradicted])
    assert any(e.code == IntegrityCode.NA_CONTRADICTED_BY_FINDING for e in rep.integrity_errors)


def test_unknown_applicability_stays_in_denominator():
    unknown = WstgTestState("B", applicability=Applicability.UNKNOWN)
    rep = compute_wstg_coverage([_completed("A"), unknown])
    assert rep.denominator == 2  # unknown stays in
    assert rep.coverage_pct == 50.0
    assert rep.unknown_applicability == 1


def test_out_of_scope_excluded_from_denominator_but_shown():
    oos = WstgTestState("B", scope=Scope.OUT_OF_SCOPE)
    rep = compute_wstg_coverage([_completed("A"), oos])
    assert rep.denominator == 1
    assert rep.out_of_scope == 1
    assert rep.coverage_pct == 100.0


def test_limited_vs_complete_disambiguation():
    # Gate passes but an unknown test remains → limited, not complete.
    states = [_completed(f"C{i}") for i in range(9)]
    states.append(WstgTestState("U", applicability=Applicability.UNKNOWN))
    rep = compute_wstg_coverage(states)
    assert rep.coverage_gate_passed is True
    assert rep.assessment_status == AssessmentStatus.LIMITED


def test_empty_states_is_null_not_zero():
    rep = compute_wstg_coverage([])
    assert rep.denominator == 0
    assert rep.coverage_pct is None
    assert rep.coverage_gate_passed is False
