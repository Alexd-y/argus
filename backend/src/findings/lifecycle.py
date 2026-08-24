"""Finding lifecycle — AI never deletes findings/evidence (Stage F)."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Self
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictStr,
    model_validator,
)


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class FindingState(StrEnum):
    CANDIDATE = "candidate"
    MACHINE_VALIDATED = "machine_validated"
    AI_REVIEWED = "ai_reviewed"
    ANALYST_CONFIRMED = "analyst_confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED_CANDIDATE = "resolved_candidate"
    RESOLVED = "resolved"
    REGRESSED = "regressed"


TERMINAL_FINDING_STATES: Final[frozenset[FindingState]] = frozenset(
    {
        FindingState.FALSE_POSITIVE,
        FindingState.ACCEPTED_RISK,
        FindingState.RESOLVED,
    }
)

_ALLOWED_TRANSITIONS: Final[dict[FindingState, frozenset[FindingState]]] = {
    FindingState.CANDIDATE: frozenset(
        {
            FindingState.MACHINE_VALIDATED,
            FindingState.FALSE_POSITIVE,
            FindingState.ACCEPTED_RISK,
        }
    ),
    FindingState.MACHINE_VALIDATED: frozenset(
        {
            FindingState.AI_REVIEWED,
            FindingState.ANALYST_CONFIRMED,
            FindingState.FALSE_POSITIVE,
            FindingState.RESOLVED_CANDIDATE,
        }
    ),
    FindingState.AI_REVIEWED: frozenset(
        {
            FindingState.ANALYST_CONFIRMED,
            FindingState.FALSE_POSITIVE,
            FindingState.ACCEPTED_RISK,
            FindingState.RESOLVED_CANDIDATE,
        }
    ),
    FindingState.ANALYST_CONFIRMED: frozenset(
        {
            FindingState.FALSE_POSITIVE,
            FindingState.ACCEPTED_RISK,
            FindingState.RESOLVED_CANDIDATE,
        }
    ),
    FindingState.RESOLVED_CANDIDATE: frozenset(
        {
            FindingState.RESOLVED,
            FindingState.REGRESSED,
        }
    ),
    FindingState.RESOLVED: frozenset({FindingState.REGRESSED}),
    FindingState.REGRESSED: frozenset(
        {
            FindingState.MACHINE_VALIDATED,
            FindingState.ANALYST_CONFIRMED,
            FindingState.RESOLVED_CANDIDATE,
        }
    ),
    FindingState.FALSE_POSITIVE: frozenset({FindingState.REGRESSED}),
    FindingState.ACCEPTED_RISK: frozenset({FindingState.REGRESSED}),
}


class InvalidFindingTransitionError(ValueError):
    """Raised when a finding state transition is not allowed."""


class FindingAssessment(BaseModel):
    """LLM/analyst assessment attached to a finding — never deletes it."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: StrictStr = Field(default_factory=lambda: str(uuid4()))
    assessment_id: StrictStr = Field(default_factory=lambda: str(uuid4()))
    finding_key: StrictStr
    tenant_id: StrictStr | None = None
    assessor: StrictStr = "ai"
    created_by: StrictStr = "ai"
    classification: StrictStr | None = None
    proposed_state: FindingState | None = None
    observation: StrictStr = ""
    inference: StrictStr = ""
    rationale: StrictStr = ""
    missing_evidence: tuple[StrictStr, ...] = ()
    citation_ids: tuple[StrictStr, ...] = ()
    evidence_refs: tuple[StrictStr, ...] = ()
    confidence: StrictFloat = Field(default=0.0, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=_utcnow)


class FindingOccurrence(BaseModel):
    """Single scanner occurrence bound to a logical finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    occurrence_key: StrictStr = Field(min_length=64, max_length=64)
    finding_key: StrictStr = Field(min_length=64, max_length=64)
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    scan_id: StrictStr = Field(min_length=1, max_length=36)
    scanner: StrictStr
    detector_id: StrictStr
    detector_version: StrictStr
    evidence_refs: tuple[StrictStr, ...] = ()
    first_seen_at: datetime
    last_seen_at: datetime

    @model_validator(mode="after")
    def _timestamps_ordered(self) -> Self:
        if self.last_seen_at < self.first_seen_at:
            raise ValueError("last_seen_at must be >= first_seen_at")
        return self


class LogicalFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_key: StrictStr
    tenant_id: StrictStr
    engagement_id: StrictStr
    state: FindingState = FindingState.CANDIDATE
    title: StrictStr = ""
    category: StrictStr = ""
    evidence_refs: list[StrictStr] = Field(default_factory=list)
    assessments: list[FindingAssessment] = Field(default_factory=list)
    occurrence_keys: list[StrictStr] = Field(default_factory=list)
    coverage_equivalent: bool = False


class FindingLifecycle(BaseModel):
    """Mutable lifecycle wrapper for a logical finding."""

    model_config = ConfigDict(extra="forbid")

    finding_key: StrictStr = Field(min_length=64, max_length=64)
    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    engagement_id: StrictStr = Field(min_length=1, max_length=36)
    state: FindingState = FindingState.CANDIDATE
    assessments: tuple[FindingAssessment, ...] = ()
    updated_at: datetime = Field(default_factory=_utcnow)

    def can_transition(self, target: FindingState) -> bool:
        allowed = _ALLOWED_TRANSITIONS.get(self.state, frozenset())
        return target in allowed

    def transition(self, target: FindingState) -> Self:
        if not self.can_transition(target):
            raise InvalidFindingTransitionError(
                f"invalid finding transition: {self.state.value} -> {target.value}"
            )
        self.state = target
        self.updated_at = _utcnow()
        return self

    def add_assessment(self, assessment: FindingAssessment) -> Self:
        if assessment.finding_key != self.finding_key:
            raise ValueError("assessment finding_key mismatch")
        self.assessments = (*self.assessments, assessment)
        if assessment.proposed_state is not None and self.can_transition(
            assessment.proposed_state
        ):
            self.state = assessment.proposed_state
            self.updated_at = assessment.created_at
        return self


def apply_assessment(
    lifecycle: FindingLifecycle,
    assessment: FindingAssessment,
) -> FindingLifecycle:
    """Apply an assessment — never deletes finding or evidence."""
    return lifecycle.add_assessment(assessment)


def validate_transition(current: FindingState, target: FindingState) -> None:
    allowed = _ALLOWED_TRANSITIONS.get(current, frozenset())
    if target not in allowed:
        raise InvalidFindingTransitionError(
            f"invalid finding transition: {current.value} -> {target.value}"
        )


class FindingLifecycleService:
    """Mutations that preserve evidence immutability."""

    def attach_assessment(
        self, finding: LogicalFinding, assessment: FindingAssessment
    ) -> LogicalFinding:
        if assessment.finding_key != finding.finding_key:
            raise ValueError("assessment_finding_key_mismatch")
        finding.assessments.append(assessment)
        if finding.state is FindingState.CANDIDATE or finding.state is FindingState.MACHINE_VALIDATED:
            finding.state = FindingState.AI_REVIEWED
        return finding

    def mark_false_positive(self, finding: LogicalFinding) -> LogicalFinding:
        finding.state = FindingState.FALSE_POSITIVE
        return finding

    def propose_resolved_candidate(
        self, finding: LogicalFinding, *, coverage_equivalent: bool
    ) -> LogicalFinding:
        """Absence without coverage cannot resolve (master §11)."""
        if not coverage_equivalent:
            finding.coverage_equivalent = False
            return finding
        finding.coverage_equivalent = True
        if finding.state not in {
            FindingState.FALSE_POSITIVE,
            FindingState.ACCEPTED_RISK,
            FindingState.RESOLVED,
        }:
            finding.state = FindingState.RESOLVED_CANDIDATE
        return finding

    def confirm_resolved_via_retest(self, finding: LogicalFinding) -> LogicalFinding:
        if finding.state is FindingState.RESOLVED_CANDIDATE:
            finding.state = FindingState.RESOLVED
        return finding

    def mark_regressed(self, finding: LogicalFinding) -> LogicalFinding:
        if finding.state in {FindingState.RESOLVED, FindingState.RESOLVED_CANDIDATE}:
            finding.state = FindingState.REGRESSED
        return finding

    def delete_finding(self, finding: LogicalFinding) -> None:
        """Explicitly forbidden — AI/automation must not delete findings."""
        del finding
        raise RuntimeError("finding_deletion_forbidden")

    def to_dict(self, finding: LogicalFinding) -> dict[str, Any]:
        return finding.model_dump(mode="json")
