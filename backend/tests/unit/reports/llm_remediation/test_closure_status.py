"""Deterministic closure-status computation (prompt L02–L06, L24)."""

from src.reports.llm_remediation.closure_status import (
    ClosureComputationInput,
    RetestExecution,
    RetestOutcome,
    compute_permitted_closure_status,
)
from src.reports.llm_remediation.schemas import PermittedClosureStatus


def test_no_retest_is_not_retested():
    """L02: describing a fix is not a fix — no retest => not_retested."""
    result = compute_permitted_closure_status(
        ClosureComputationInput(finding_id="F-1", acceptance_criteria_ids=("C1", "C2"))
    )
    assert result.permitted_status is PermittedClosureStatus.NOT_RETESTED
    assert result.untested_criteria_ids == ["C1", "C2"]
    assert result.supporting_retest_ids == []


def test_all_criteria_pass_is_fixed_verified():
    """L05: every criterion satisfied by an evidence-backed retest."""
    result = compute_permitted_closure_status(
        ClosureComputationInput(
            finding_id="F-1",
            acceptance_criteria_ids=("C1", "C2"),
            retests=(RetestExecution("T1", RetestOutcome.PASS_SECURE, ("C1", "C2"), ("E1",)),),
        )
    )
    assert result.permitted_status is PermittedClosureStatus.FIXED_VERIFIED
    assert set(result.satisfied_criteria_ids) == {"C1", "C2"}
    assert result.supporting_retest_ids == ["T1"]
    assert result.supporting_evidence_ids == ["E1"]


def test_partial_close_is_partially_fixed():
    """L04: closing one asset/criterion does not close the rest."""
    result = compute_permitted_closure_status(
        ClosureComputationInput(
            finding_id="F-1",
            acceptance_criteria_ids=("C1", "C2"),
            retests=(RetestExecution("T1", RetestOutcome.PASS_SECURE, ("C1",), ("E1",)),),
        )
    )
    assert result.permitted_status is PermittedClosureStatus.PARTIALLY_FIXED
    assert result.satisfied_criteria_ids == ["C1"]
    assert result.untested_criteria_ids == ["C2"]


def test_failing_retest_is_open():
    result = compute_permitted_closure_status(
        ClosureComputationInput(
            finding_id="F-1",
            acceptance_criteria_ids=("C1",),
            retests=(RetestExecution("T1", RetestOutcome.FAIL_VULNERABLE, ("C1",)),),
        )
    )
    assert result.permitted_status is PermittedClosureStatus.OPEN
    assert result.unsatisfied_criteria_ids == ["C1"]


def test_risk_accepted_never_fixed_verified():
    """L06: risk accepted is not fixed_verified."""
    result = compute_permitted_closure_status(
        ClosureComputationInput(
            finding_id="F-1",
            acceptance_criteria_ids=("C1",),
            retests=(RetestExecution("T1", RetestOutcome.PASS_SECURE, ("C1",), ("E1",)),),
            risk_accepted=True,
        )
    )
    assert result.permitted_status is PermittedClosureStatus.RISK_ACCEPTED


def test_unreachable_target_is_inconclusive():
    """L24: unreachable target / expired session is not a successful retest."""
    result = compute_permitted_closure_status(
        ClosureComputationInput(
            finding_id="F-1",
            acceptance_criteria_ids=("C1",),
            retests=(RetestExecution("T1", RetestOutcome.UNREACHABLE, ("C1",)),),
        )
    )
    assert result.permitted_status is PermittedClosureStatus.INCONCLUSIVE


def test_false_positive_short_circuits():
    result = compute_permitted_closure_status(
        ClosureComputationInput(
            finding_id="F-1", acceptance_criteria_ids=("C1",), is_false_positive=True
        )
    )
    assert result.permitted_status is PermittedClosureStatus.FALSE_POSITIVE
