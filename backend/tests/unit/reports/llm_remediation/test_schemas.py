"""Strict-contract invariants for the Valhalla LLM analysis schemas."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from src.reports.llm_remediation.schemas import (
    AcceptanceCriterion,
    AnalysisStatus,
    EstablishedOrHypothesis,
    FindingClosureConclusion,
    FindingRemediationAnalysis,
    FixStep,
    LlmProvenance,
    PermittedClosureStatus,
    PriorityRationale,
    RetestStep,
    RootCause,
    closure_rank,
)


def _provenance() -> LlmProvenance:
    return LlmProvenance(
        analysis_id="a-1",
        provider="mock",
        model="mock-1",
        prompt_version="v1",
        schema_version="v1",
        input_hash="abcdef12",
        generated_at=datetime.now(UTC),
        validation_status="validated",
    )


def _valid_remediation(**overrides):
    base = {
        "finding_id": "F-1",
        "analysis_status": AnalysisStatus.GENERATED_VALIDATED,
        "root_cause": RootCause(
            text="cause", established_or_hypothesis=EstablishedOrHypothesis.ESTABLISHED
        ),
        "remediation_objective": "objective",
        "permanent_fix_steps": [
            FixStep(step_id="S1", component="web", action="do", rationale="why")
        ],
        "priority_rationale": PriorityRationale(text="p"),
        "acceptance_criteria": [
            AcceptanceCriterion(criterion_id="C1", measurable_property="m", required_evidence="e")
        ],
        "retest_plan": [RetestStep(test_id="T1", procedure="p", expected_secure_result="ok")],
        "source_context_hash": "hash1234",
        "llm_provenance": _provenance(),
    }
    base.update(overrides)
    return base


def test_generated_validated_requires_steps_criteria_retest():
    FindingRemediationAnalysis.model_validate(_valid_remediation())  # ok

    with pytest.raises(ValidationError):
        FindingRemediationAnalysis.model_validate(_valid_remediation(permanent_fix_steps=[]))
    with pytest.raises(ValidationError):
        FindingRemediationAnalysis.model_validate(_valid_remediation(acceptance_criteria=[]))
    with pytest.raises(ValidationError):
        FindingRemediationAnalysis.model_validate(_valid_remediation(retest_plan=[]))


def test_non_validated_requires_missing_information():
    with pytest.raises(ValidationError):
        FindingRemediationAnalysis.model_validate(
            _valid_remediation(
                analysis_status=AnalysisStatus.INSUFFICIENT_CONTEXT, missing_information=[]
            )
        )
    # With gaps listed it is accepted.
    FindingRemediationAnalysis.model_validate(
        _valid_remediation(
            analysis_status=AnalysisStatus.INSUFFICIENT_CONTEXT,
            missing_information=["stack unknown"],
        )
    )


def test_extra_fields_forbidden():
    with pytest.raises(ValidationError):
        FindingRemediationAnalysis.model_validate(_valid_remediation(nonsense_field=1))


def test_fixed_verified_requires_all_satisfied_and_retest():
    prov = _provenance()
    # Missing supporting retest → invalid.
    with pytest.raises(ValidationError):
        FindingClosureConclusion(
            finding_id="F-1",
            permitted_closure_status=PermittedClosureStatus.FIXED_VERIFIED,
            conclusion_text="closed",
            satisfied_criteria_ids=["C1"],
            residual_risk="none",
            source_context_hash="hash1234",
            llm_provenance=prov,
        )
    # Untested criterion present → invalid.
    with pytest.raises(ValidationError):
        FindingClosureConclusion(
            finding_id="F-1",
            permitted_closure_status=PermittedClosureStatus.FIXED_VERIFIED,
            conclusion_text="closed",
            satisfied_criteria_ids=["C1"],
            untested_criteria_ids=["C2"],
            supporting_retest_ids=["T1"],
            residual_risk="none",
            source_context_hash="hash1234",
            llm_provenance=prov,
        )
    # Fully proven → valid.
    FindingClosureConclusion(
        finding_id="F-1",
        permitted_closure_status=PermittedClosureStatus.FIXED_VERIFIED,
        conclusion_text="closed",
        satisfied_criteria_ids=["C1"],
        supporting_retest_ids=["T1"],
        residual_risk="none",
        source_context_hash="hash1234",
        llm_provenance=prov,
    )


def test_closure_rank_monotonic():
    assert closure_rank(PermittedClosureStatus.FIXED_VERIFIED) > closure_rank(
        PermittedClosureStatus.NOT_RETESTED
    )
    assert closure_rank(PermittedClosureStatus.PARTIALLY_FIXED) > closure_rank(
        PermittedClosureStatus.OPEN
    )
