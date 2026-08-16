"""Coverage accounting — honest status resolution (Stage E)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Final

from src.capabilities.schemas import (
    COVERED_STATUSES,
    CoverageRequirement,
    CoverageResult,
    CoverageStatus,
)
from src.core.unified_ai_metrics import record_coverage_requirement
from src.eval.rates import record_coverage_transition


class CoverageAccountingError(ValueError):
    """Raised when coverage status would violate accounting invariants."""


_BLOCKED_REASONS: Final[frozenset[str]] = frozenset(
    {
        "policy_blocked",
        "tool_error",
        "target_unreachable",
        "not_executed",
        "approval_denied",
        "deadline_reached",
        "circuit_open",
    }
)

COVERAGE_REASON_CODES: Final[frozenset[str]] = frozenset(
    {
        *_BLOCKED_REASONS,
        "executed",
        "budget_partial",
        "fingerprint_mismatch",
        "not_scheduled_by_quick_profile",
    }
)


def is_allowed_coverage_reason(reason: str | None) -> bool:
    """True when ``reason`` is on the coverage reason-code whitelist."""
    if not reason:
        return False
    return reason.strip() in COVERAGE_REASON_CODES


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def is_covered_status(status: CoverageStatus) -> bool:
    return status in COVERED_STATUSES


def can_transition_coverage(
    current: CoverageStatus,
    proposed: CoverageStatus,
    *,
    has_execution_evidence: bool,
    has_finding: bool,
    record_eval: bool = True,
) -> bool:
    """Return whether ``proposed`` is an honest transition from ``current``."""
    allowed = _can_transition_coverage(
        current,
        proposed,
        has_execution_evidence=has_execution_evidence,
        has_finding=has_finding,
    )
    if record_eval:
        record_coverage_transition(accurate=allowed)
    return allowed


def _can_transition_coverage(
    current: CoverageStatus,
    proposed: CoverageStatus,
    *,
    has_execution_evidence: bool,
    has_finding: bool,
) -> bool:
    if proposed is CoverageStatus.NOT_TESTED:
        return current is CoverageStatus.PLANNED

    if proposed in COVERED_STATUSES and not has_execution_evidence:
        return False

    if proposed is CoverageStatus.COVERED_NO_FINDING and has_finding:
        return False

    if proposed is CoverageStatus.COVERED_WITH_FINDING and not has_finding:
        return False

    if current is CoverageStatus.NOT_TESTED and proposed is CoverageStatus.COVERED_NO_FINDING:
        return has_execution_evidence

    if current is CoverageStatus.NOT_TESTED and proposed is CoverageStatus.COVERED_WITH_FINDING:
        return has_execution_evidence and has_finding

    return True


def resolve_coverage_status(
    *,
    current: CoverageStatus,
    proposed: CoverageStatus,
    execution_evidence_id: str | None = None,
    finding_id: str | None = None,
    blocked_reason: str | None = None,
    tool_executed: bool = False,
) -> CoverageStatus:
    """Resolve the next coverage status with strict execution-evidence rules.

    Invariants enforced:
    * ``not_tested`` never becomes ``covered_no_finding`` without execution evidence.
    * Absence of a finding does not imply coverage.
  * ``covered_with_finding`` requires both execution evidence and a finding id.
    """
    has_execution_evidence = bool(execution_evidence_id) or tool_executed
    has_finding = bool(finding_id)

    if proposed is CoverageStatus.BLOCKED:
        if not blocked_reason:
            record_coverage_transition(accurate=False)
            raise CoverageAccountingError("blocked status requires blocked_reason")
        record_coverage_transition(accurate=True)
        return proposed

    if proposed in COVERED_STATUSES and not has_execution_evidence:
        record_coverage_transition(accurate=False)
        raise CoverageAccountingError(
            f"cannot mark {proposed.value} without execution evidence"
        )

    if proposed is CoverageStatus.COVERED_NO_FINDING and has_finding:
        record_coverage_transition(accurate=False)
        raise CoverageAccountingError(
            "covered_no_finding incompatible with present finding_id"
        )

    if proposed is CoverageStatus.COVERED_WITH_FINDING and not has_finding:
        record_coverage_transition(accurate=False)
        raise CoverageAccountingError(
            "covered_with_finding requires finding_id"
        )

    if not can_transition_coverage(
        current,
        proposed,
        has_execution_evidence=has_execution_evidence,
        has_finding=has_finding,
        record_eval=False,
    ):
        record_coverage_transition(accurate=False)
        raise CoverageAccountingError(
            f"invalid coverage transition: {current.value} -> {proposed.value}"
        )

    record_coverage_transition(accurate=True)
    return proposed


def infer_status_from_execution(
    *,
    tool_executed: bool,
    tool_error: bool,
    target_unreachable: bool,
    finding_id: str | None = None,
    execution_evidence_id: str | None = None,
    policy_blocked: bool = False,
    not_applicable: bool = False,
) -> CoverageStatus:
    """Map raw execution signals to an honest coverage status."""
    if not_applicable:
        return CoverageStatus.NOT_APPLICABLE
    if policy_blocked:
        return CoverageStatus.BLOCKED
    if target_unreachable:
        return CoverageStatus.BLOCKED
    if tool_error:
        return CoverageStatus.BLOCKED
    if not tool_executed:
        return CoverageStatus.NOT_TESTED
    if finding_id:
        return CoverageStatus.COVERED_WITH_FINDING
    if execution_evidence_id:
        return CoverageStatus.COVERED_NO_FINDING
    return CoverageStatus.NOT_TESTED


def build_coverage_result(
    requirement: CoverageRequirement,
    *,
    status: CoverageStatus,
    execution_evidence_id: str | None = None,
    blocked_reason: str | None = None,
    finding_id: str | None = None,
    current: CoverageStatus = CoverageStatus.NOT_TESTED,
    tool_executed: bool = False,
    mode: str = "production",
    reason_code: str | None = None,
    template_ids: tuple[str, ...] = (),
    evidence_ids: tuple[str, ...] = (),
) -> CoverageResult:
    """Construct a validated :class:`CoverageResult` for a requirement."""
    resolved = resolve_coverage_status(
        current=current,
        proposed=status,
        execution_evidence_id=execution_evidence_id,
        finding_id=finding_id,
        blocked_reason=blocked_reason,
        tool_executed=tool_executed,
    )
    record_coverage_requirement(status=resolved.value, mode=mode)
    return CoverageResult(
        requirement_id=requirement.id,
        tenant_id=requirement.tenant_id,
        scan_id=requirement.scan_id,
        asset_id=requirement.asset_id,
        capability_id=requirement.capability_id,
        status=resolved,
        execution_evidence_id=execution_evidence_id,
        blocked_reason=blocked_reason,
        finding_id=finding_id,
        recorded_at=_utcnow(),
        reason_code=reason_code or blocked_reason,
        template_ids=tuple(template_ids),
        evidence_ids=tuple(evidence_ids),
    )


def absence_of_finding_is_not_coverage(
    *,
    prior_status: CoverageStatus,
    finding_present: bool,
    execution_evidence_id: str | None,
) -> CoverageStatus:
    """Explicit guard: missing finding without execution cannot imply coverage."""
    if finding_present:
        return CoverageStatus.COVERED_WITH_FINDING
    if execution_evidence_id:
        return CoverageStatus.COVERED_NO_FINDING
    if prior_status is CoverageStatus.RUNNING:
        return CoverageStatus.NOT_TESTED
    return prior_status
