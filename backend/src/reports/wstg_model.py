"""Shared WSTG coverage domain model (ARGUS-WSTG-COV-1).

This module is the single home for the independent measurement dimensions the
WSTG coverage subsystem reasons about. Keeping them here (rather than in
``wstg_gate``) lets the gate, applicability, execution, evidence and plan
modules share one vocabulary without import cycles.

Design invariants (see ``docs/wstg-coverage.md``):

* **Scope**, **applicability**, **execution** and **security outcome** are
  orthogonal. A confirmed vulnerability (outcome=fail) can coexist with a
  partially executed test; execution status never implies a security verdict and
  vice-versa.
* Running a tool is *not* coverage. Only a completed execution with a determined
  outcome and *validated* evidence counts.
* ``unknown`` is a first-class state — it keeps a test in the denominator; it is
  never used to shrink it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Scope(StrEnum):
    """Whether a test is part of the agreed engagement scope."""

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"


class Applicability(StrEnum):
    """Whether the test is applicable to the target (independent of execution)."""

    APPLICABLE = "applicable"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class ExecutionStatus(StrEnum):
    """Lifecycle of a test's execution (independent of the security outcome)."""

    NOT_STARTED = "not_started"
    RUNNING = "running"
    PARTIAL = "partial"
    COMPLETED = "completed"
    BLOCKED = "blocked"
    FAILED = "failed"


class Outcome(StrEnum):
    """Security result of a test (independent of how completely it executed)."""

    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"
    NOT_EVALUATED = "not_evaluated"


class ReasonCode(StrEnum):
    """Why a test could not be completed / why it was excluded."""

    MISSING_CREDENTIALS = "missing_credentials"
    MISSING_ROLE = "missing_role"
    UNSUPPORTED = "unsupported"
    MANUAL_REQUIRED = "manual_required"
    TOOL_UNAVAILABLE = "tool_unavailable"
    TIMEOUT = "timeout"
    DISCOVERY_INCOMPLETE = "discovery_incomplete"
    FEATURE_ABSENT = "feature_absent"
    OUT_OF_SCOPE = "out_of_scope"
    OTHER = "other"


class AssessmentStatus(StrEnum):
    """Overall report verdict (see gate priority in docs/wstg-coverage.md)."""

    COMPLETE = "complete"
    LIMITED = "limited"
    INCOMPLETE = "incomplete"
    INVALID = "invalid"


@dataclass(frozen=True)
class ApplicabilityDecision:
    """A structured, auditable applicability decision for one test/scenario.

    A ``NOT_APPLICABLE`` decision is only honoured by the gate when it carries a
    matching rule, a non-blank rationale and evidence that the required condition
    is absent in scope (validated separately). ``UNKNOWN`` keeps the test in the
    denominator.
    """

    test_id: str
    state: Applicability
    reason_code: ReasonCode | None = None
    rationale: str = ""
    evidence_refs: tuple[str, ...] = ()
    rule_id: str | None = None
    rule_version: str | None = None
    scope_version: str | None = None
    scenario_id: str | None = None
    decided_at: str | None = None
    source: str | None = None

    def rationale_is_blank(self) -> bool:
        return not self.rationale or not self.rationale.strip()

    def is_valid_not_applicable(self) -> bool:
        """A NOT_APPLICABLE decision is valid only when fully substantiated."""
        return (
            self.state == Applicability.NOT_APPLICABLE
            and self.rule_id is not None
            and not self.rationale_is_blank()
            and bool(self.evidence_refs)
        )


@dataclass
class WstgTestState:
    """Per-test coverage state consumed by the pure gate.

    All IO (evidence resolution, artifact fetch) happens *before* a state is
    built: ``evidence_validated`` is the already-resolved verdict, so the gate
    stays a pure function.
    """

    test_id: str
    category: str | None = None
    scope: Scope = Scope.IN_SCOPE
    applicability: Applicability = Applicability.APPLICABLE
    applicability_valid: bool = True
    reason_code: ReasonCode | None = None
    rationale: str = ""
    execution_status: ExecutionStatus = ExecutionStatus.NOT_STARTED
    outcome: Outcome = Outcome.NOT_EVALUATED
    evidence_refs: list[str] = field(default_factory=list)
    evidence_validated: bool = False
    required_scenarios_completed: bool = True
    completion_criteria_met: bool = False
    conflict: bool = False
    scenario_ids: list[str] = field(default_factory=list)

    # ---- dimension helpers -------------------------------------------------
    def in_scope(self) -> bool:
        return self.scope == Scope.IN_SCOPE

    def is_validly_not_applicable(self) -> bool:
        return self.applicability == Applicability.NOT_APPLICABLE and self.applicability_valid

    def in_denominator(self) -> bool:
        """A test counts toward the denominator unless it is out-of-scope or a
        *validly* excluded not-applicable. ``unknown`` stays in."""
        return self.in_scope() and not self.is_validly_not_applicable()

    def counts_toward_coverage(self) -> bool:
        """Numerator membership — a fully-completed, evidenced, determined test."""
        return (
            self.in_denominator()
            and self.applicability != Applicability.NOT_APPLICABLE
            and self.execution_status == ExecutionStatus.COMPLETED
            and self.outcome in (Outcome.PASS, Outcome.FAIL)
            and self.evidence_validated
            and self.completion_criteria_met
            and self.required_scenarios_completed
            and not self.conflict
        )

    def has_unjustified_exclusion(self) -> bool:
        """True when applicability is NOT_APPLICABLE but the decision is invalid,
        or when applicable=False is asserted without a valid decision."""
        return self.applicability == Applicability.NOT_APPLICABLE and not self.applicability_valid

    def na_contradicted_by_finding(self) -> bool:
        """A test excluded as N/A but showing a confirmed fail is a contradiction."""
        return self.applicability == Applicability.NOT_APPLICABLE and self.outcome == Outcome.FAIL


__all__ = [
    "Applicability",
    "ApplicabilityDecision",
    "AssessmentStatus",
    "ExecutionStatus",
    "Outcome",
    "ReasonCode",
    "Scope",
    "WstgTestState",
]
