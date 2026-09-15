"""Strict Pydantic contracts for the mandatory Valhalla per-finding LLM analysis.

These models are the machine-checkable interface between the LLM and the report
pipeline. They are intentionally strict (``extra="forbid"``, bounded lengths,
enums, cross-field invariants) so that a hallucinated, over-confident or
schema-violating model response is rejected *before* it can reach a customer
deliverable.

Two independent questions are modelled separately (prompt §1):

* :class:`FindingRemediationAnalysis` — *how* to fix a finding.
* :class:`FindingClosureConclusion` — *whether* a finding is actually closed,
  bounded by an application-computed ``permitted_closure_status`` that the model
  is not allowed to strengthen.

:class:`ReportClosureSummary` is the report-wide synthesis built from the
accepted per-finding analyses.

Security invariants: the models never carry raw secrets — only resolvable
reference IDs and redacted fragments (SI-3). No hidden chain-of-thought is
stored; ``llm_provenance`` keeps only short, verifiable audit fields.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

# ---------------------------------------------------------------------------
# Bounded-length aliases (defence against unbounded model output).
# ---------------------------------------------------------------------------

_SHORT = 200
_ID = 128
_TEXT = 4000
_LIST = 64

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AnalysisStatus(StrEnum):
    """Lifecycle of a per-finding remediation analysis (prompt §7)."""

    GENERATED_VALIDATED = "generated_validated"
    NEEDS_REVIEW = "needs_review"
    INSUFFICIENT_CONTEXT = "insufficient_context"
    FAILED = "failed"


class EstablishedOrHypothesis(StrEnum):
    """Whether a claimed root cause is proven or merely hypothesised."""

    ESTABLISHED = "established"
    HYPOTHESIS = "hypothesis"
    UNKNOWN = "unknown"


class PermittedClosureStatus(StrEnum):
    """Application-computed closure status (prompt §7, §13).

    Ordered from weakest to strongest claim. ``fixed_verified`` is the only
    status that asserts a proven fix and may only be produced by a verifiable
    retest — never by model text alone.
    """

    OPEN = "open"
    NOT_RETESTED = "not_retested"
    INCONCLUSIVE = "inconclusive"
    PARTIALLY_FIXED = "partially_fixed"
    RISK_ACCEPTED = "risk_accepted"
    FALSE_POSITIVE = "false_positive"
    FIXED_VERIFIED = "fixed_verified"


# Strength ranking used to forbid the model from *strengthening* the computed
# status. A model may downgrade (report a weaker claim) but never upgrade.
_CLOSURE_RANK: dict[PermittedClosureStatus, int] = {
    PermittedClosureStatus.OPEN: 0,
    PermittedClosureStatus.NOT_RETESTED: 1,
    PermittedClosureStatus.INCONCLUSIVE: 1,
    PermittedClosureStatus.PARTIALLY_FIXED: 2,
    PermittedClosureStatus.RISK_ACCEPTED: 2,
    PermittedClosureStatus.FALSE_POSITIVE: 3,
    PermittedClosureStatus.FIXED_VERIFIED: 4,
}


def closure_rank(status: PermittedClosureStatus) -> int:
    """Return the monotonic strength rank of a closure status."""

    return _CLOSURE_RANK[status]


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


class LlmProvenance(BaseModel):
    """Short, verifiable audit trail for one accepted LLM output.

    Deliberately excludes any hidden chain-of-thought (prompt §7): it records
    only *what* produced the output and *whether it validated*, not the model's
    private reasoning.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    analysis_id: str = Field(min_length=1, max_length=_ID)
    provider: str = Field(min_length=1, max_length=_SHORT)
    model: str = Field(min_length=1, max_length=_SHORT)
    prompt_version: str = Field(min_length=1, max_length=_SHORT)
    schema_version: str = Field(min_length=1, max_length=_SHORT)
    input_hash: str = Field(min_length=8, max_length=_ID)
    generated_at: datetime
    validation_status: str = Field(min_length=1, max_length=_SHORT)
    token_usage: int | None = Field(default=None, ge=0)
    cost_usd: float | None = Field(default=None, ge=0.0)


# ---------------------------------------------------------------------------
# Remediation analysis
# ---------------------------------------------------------------------------


class RootCause(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=_TEXT)
    established_or_hypothesis: EstablishedOrHypothesis
    evidence_ids: list[str] = Field(default_factory=list, max_length=_LIST)


class FixStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str = Field(min_length=1, max_length=_ID)
    component: str = Field(min_length=1, max_length=_SHORT)
    action: str = Field(min_length=1, max_length=_TEXT)
    rationale: str = Field(min_length=1, max_length=_TEXT)
    prerequisites: list[str] = Field(default_factory=list, max_length=_LIST)
    applicable_finding_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    source_reference_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    acceptance_criteria_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    conditional_config_or_patch: str | None = Field(default=None, max_length=_TEXT)
    implementation_risks: list[str] = Field(default_factory=list, max_length=_LIST)
    rollback_considerations: str | None = Field(default=None, max_length=_TEXT)


class AcceptanceCriterion(BaseModel):
    model_config = ConfigDict(extra="forbid")

    criterion_id: str = Field(min_length=1, max_length=_ID)
    measurable_property: str = Field(min_length=1, max_length=_TEXT)
    required_evidence: str = Field(min_length=1, max_length=_TEXT)


class RetestStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    test_id: str = Field(min_length=1, max_length=_ID)
    criteria_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    preconditions: str | None = Field(default=None, max_length=_TEXT)
    procedure: str = Field(min_length=1, max_length=_TEXT)
    expected_secure_result: str = Field(min_length=1, max_length=_TEXT)
    positive_control: str | None = Field(default=None, max_length=_TEXT)
    relevant_bypass_cases: list[str] = Field(default_factory=list, max_length=_LIST)
    evidence_required: list[str] = Field(default_factory=list, max_length=_LIST)
    scope_constraints: str | None = Field(default=None, max_length=_TEXT)


class PriorityRationale(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(min_length=1, max_length=_TEXT)
    fact_refs: list[str] = Field(default_factory=list, max_length=_LIST)
    assumptions: list[str] = Field(default_factory=list, max_length=_LIST)


class FindingRemediationAnalysis(BaseModel):
    """Individual engineering remediation plan for a single finding."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=_ID)
    analysis_status: AnalysisStatus
    root_cause: RootCause
    remediation_objective: str = Field(min_length=1, max_length=_TEXT)
    immediate_containment: list[str] = Field(default_factory=list, max_length=_LIST)
    permanent_fix_steps: list[FixStep] = Field(default_factory=list, max_length=_LIST)
    preventive_measures: list[str] = Field(default_factory=list, max_length=_LIST)
    suggested_owner: str | None = Field(default=None, max_length=_SHORT)
    assigned_owner: str | None = Field(default=None, max_length=_SHORT)
    suggested_deadline: str | None = Field(default=None, max_length=_SHORT)
    agreed_deadline: str | None = Field(default=None, max_length=_SHORT)
    dependencies: list[str] = Field(default_factory=list, max_length=_LIST)
    priority_rationale: PriorityRationale
    acceptance_criteria: list[AcceptanceCriterion] = Field(default_factory=list, max_length=_LIST)
    retest_plan: list[RetestStep] = Field(default_factory=list, max_length=_LIST)
    missing_information: list[str] = Field(default_factory=list, max_length=_LIST)
    assumptions: list[str] = Field(default_factory=list, max_length=_LIST)
    source_finding_version: str | None = Field(default=None, max_length=_SHORT)
    source_context_hash: str = Field(min_length=8, max_length=_ID)
    llm_provenance: LlmProvenance

    @model_validator(mode="after")
    def _validate_completeness(self) -> Self:
        # A fully generated & validated plan must carry concrete, individual
        # steps, acceptance criteria and a retest — not a single generic phrase
        # (prompt §9.4). Weaker statuses must justify themselves with an
        # explicit list of gaps (prompt §9 / §8.1 "insufficient_context").
        if self.analysis_status == AnalysisStatus.GENERATED_VALIDATED:
            if not self.permanent_fix_steps:
                raise ValueError(
                    "generated_validated analysis requires at least one permanent_fix_step"
                )
            if not self.acceptance_criteria:
                raise ValueError(
                    "generated_validated analysis requires at least one acceptance_criterion"
                )
            if not self.retest_plan:
                raise ValueError(
                    "generated_validated analysis requires at least one retest_plan step"
                )
        elif not self.missing_information:
            raise ValueError(
                f"analysis_status={self.analysis_status.value} requires a non-empty "
                "missing_information list explaining the gaps"
            )
        return self


# ---------------------------------------------------------------------------
# Closure conclusion
# ---------------------------------------------------------------------------


class FindingClosureConclusion(BaseModel):
    """Evidence-bounded conclusion about whether a finding is closed."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(min_length=1, max_length=_ID)
    permitted_closure_status: PermittedClosureStatus
    conclusion_text: str = Field(min_length=1, max_length=_TEXT)
    satisfied_criteria_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    unsatisfied_criteria_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    untested_criteria_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    supporting_retest_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    supporting_evidence_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    residual_risk: str = Field(min_length=1, max_length=_TEXT)
    next_actions: list[str] = Field(default_factory=list, max_length=_LIST)
    blockers: list[str] = Field(default_factory=list, max_length=_LIST)
    source_context_hash: str = Field(min_length=8, max_length=_ID)
    llm_provenance: LlmProvenance

    @model_validator(mode="after")
    def _validate_status_consistency(self) -> Self:
        # ``fixed_verified`` is the strongest claim and demands proof: every
        # criterion satisfied, none untested/unsatisfied, and at least one
        # supporting retest (prompt L02/L05). This is defence-in-depth on top
        # of the runner's status clamp.
        if self.permitted_closure_status == PermittedClosureStatus.FIXED_VERIFIED:
            if self.unsatisfied_criteria_ids or self.untested_criteria_ids:
                raise ValueError(
                    "fixed_verified requires all acceptance criteria satisfied "
                    "(no unsatisfied/untested criteria)"
                )
            if not self.supporting_retest_ids:
                raise ValueError("fixed_verified requires at least one supporting retest id")
        return self


# ---------------------------------------------------------------------------
# Report-wide synthesis
# ---------------------------------------------------------------------------


class PriorityAction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(min_length=1, max_length=_ID)
    finding_ids: list[str] = Field(min_length=1, max_length=_LIST)
    rationale: str = Field(min_length=1, max_length=_TEXT)
    dependencies: list[str] = Field(default_factory=list, max_length=_LIST)


class ReportClosureSummary(BaseModel):
    """Report-wide LLM synthesis built from accepted per-finding analyses."""

    model_config = ConfigDict(extra="forbid")

    report_version: str = Field(min_length=1, max_length=_SHORT)
    exact_counts_by_verification_and_remediation_status: dict[str, int] = Field(
        default_factory=dict
    )
    overall_conclusion: str = Field(min_length=1, max_length=_TEXT)
    priority_actions: list[PriorityAction] = Field(default_factory=list, max_length=_LIST)
    verified_closed_finding_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    not_verified_closed_finding_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    accepted_risk_finding_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    coverage_gaps: list[str] = Field(default_factory=list, max_length=_LIST)
    decisions_required: list[str] = Field(default_factory=list, max_length=_LIST)
    source_analysis_ids: list[str] = Field(default_factory=list, max_length=_LIST)
    llm_provenance: LlmProvenance

    @model_validator(mode="after")
    def _validate_counts_nonnegative(self) -> Self:
        for key, value in self.exact_counts_by_verification_and_remediation_status.items():
            if value < 0:
                raise ValueError(f"count for {key!r} must be non-negative, got {value}")
        return self


__all__ = [
    "AcceptanceCriterion",
    "AnalysisStatus",
    "EstablishedOrHypothesis",
    "FindingClosureConclusion",
    "FindingRemediationAnalysis",
    "FixStep",
    "LlmProvenance",
    "PermittedClosureStatus",
    "PriorityAction",
    "PriorityRationale",
    "ReportClosureSummary",
    "RetestStep",
    "RootCause",
    "closure_rank",
]
