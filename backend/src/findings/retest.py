"""Targeted retest jobs for finding lifecycle (Stage F)."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr

from src.capabilities.schemas import CoverageStatus
from src.findings.diff import DiffStatus
from src.findings.lifecycle import (
    FindingLifecycle,
    FindingLifecycleService,
    FindingState,
    InvalidFindingTransitionError,
    LogicalFinding,
)


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


class RetestResultKind(StrEnum):
    STILL_PRESENT = "still_present"
    NOT_REPRODUCED = "not_reproduced"
    ERROR = "error"
    NOT_EXECUTED = "not_executed"


class RetestOutcome(StrEnum):
    STILL_PRESENT = "still_present"
    NOT_PRESENT = "not_present"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"


class RetestJob(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: StrictStr = Field(default_factory=lambda: str(uuid4()))
    job_id: StrictStr = Field(default_factory=lambda: str(uuid4()))
    finding_key: StrictStr
    tenant_id: StrictStr
    engagement_id: StrictStr | None = None
    scan_id: StrictStr | None = None
    baseline_scan_id: StrictStr | None = None
    coverage_equivalent: StrictBool = False
    status: StrictStr = "pending"
    result: RetestResultKind = RetestResultKind.NOT_EXECUTED
    created_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime | None = None


class RetestResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    job_id: StrictStr
    finding_key: StrictStr
    outcome: RetestOutcome
    diff_status: DiffStatus
    new_state: FindingState
    coverage_status: CoverageStatus
    rationale: StrictStr


class RetestResolutionError(ValueError):
    """Raised when retest cannot honestly change lifecycle state."""


def _has_equivalent_coverage(coverage_status: CoverageStatus | None) -> bool:
    return coverage_status in {
        CoverageStatus.COVERED_NO_FINDING,
        CoverageStatus.COVERED_WITH_FINDING,
        CoverageStatus.PARTIAL,
    }


def resolve_retest(
    lifecycle: FindingLifecycle,
    *,
    outcome: RetestOutcome,
    coverage_status: CoverageStatus,
    job_id: str,
) -> RetestResult:
    if outcome is RetestOutcome.BLOCKED:
        return RetestResult(
            job_id=job_id,
            finding_key=lifecycle.finding_key,
            outcome=outcome,
            diff_status=DiffStatus.NOT_TESTED,
            new_state=lifecycle.state,
            coverage_status=coverage_status,
            rationale="retest blocked",
        )

    if outcome is RetestOutcome.STILL_PRESENT:
        if lifecycle.state in {FindingState.RESOLVED_CANDIDATE, FindingState.RESOLVED}:
            lifecycle.transition(FindingState.REGRESSED)
        return RetestResult(
            job_id=job_id,
            finding_key=lifecycle.finding_key,
            outcome=outcome,
            diff_status=DiffStatus.REGRESSED,
            new_state=lifecycle.state,
            coverage_status=coverage_status,
            rationale="finding reappeared during retest",
        )

    if outcome is RetestOutcome.NOT_PRESENT:
        if not _has_equivalent_coverage(coverage_status):
            raise RetestResolutionError(
                "absence without equivalent coverage cannot resolve finding"
            )
        if lifecycle.state is FindingState.RESOLVED_CANDIDATE:
            lifecycle.transition(FindingState.RESOLVED)
            diff_status = DiffStatus.RESOLVED
            rationale = "resolved after targeted negative retest with coverage"
        elif lifecycle.state in {
            FindingState.MACHINE_VALIDATED,
            FindingState.AI_REVIEWED,
            FindingState.ANALYST_CONFIRMED,
        }:
            lifecycle.transition(FindingState.RESOLVED_CANDIDATE)
            diff_status = DiffStatus.RESOLVED_CANDIDATE
            rationale = "marked resolved_candidate after negative retest with coverage"
        else:
            diff_status = DiffStatus.RESOLVED_CANDIDATE
            rationale = "negative retest with coverage"
        return RetestResult(
            job_id=job_id,
            finding_key=lifecycle.finding_key,
            outcome=outcome,
            diff_status=diff_status,
            new_state=lifecycle.state,
            coverage_status=coverage_status,
            rationale=rationale,
        )

    return RetestResult(
        job_id=job_id,
        finding_key=lifecycle.finding_key,
        outcome=outcome,
        diff_status=DiffStatus.NOT_TESTED,
        new_state=lifecycle.state,
        coverage_status=coverage_status,
        rationale="inconclusive retest",
    )


def create_retest_job(
    *,
    tenant_id: str,
    finding_key: str,
    scan_id: str,
    baseline_scan_id: str,
) -> RetestJob:
    return RetestJob(
        tenant_id=tenant_id,
        finding_key=finding_key,
        scan_id=scan_id,
        baseline_scan_id=baseline_scan_id,
    )


def apply_retest_or_raise(
    lifecycle: FindingLifecycle,
    *,
    outcome: RetestOutcome,
    coverage_status: CoverageStatus,
    job_id: str,
) -> RetestResult:
    try:
        return resolve_retest(
            lifecycle,
            outcome=outcome,
            coverage_status=coverage_status,
            job_id=job_id,
        )
    except InvalidFindingTransitionError as exc:
        raise RetestResolutionError(str(exc)) from exc


class RetestService:
    def __init__(self, lifecycle: FindingLifecycleService | None = None) -> None:
        self._lifecycle = lifecycle or FindingLifecycleService()

    def apply_result(
        self, finding: LogicalFinding, job: RetestJob
    ) -> tuple[LogicalFinding, RetestJob]:
        job.completed_at = _utcnow()
        if job.result in {RetestResultKind.NOT_EXECUTED, RetestResultKind.ERROR}:
            return finding, job

        if job.result is RetestResultKind.NOT_REPRODUCED:
            if not job.coverage_equivalent:
                return finding, job
            finding = self._lifecycle.propose_resolved_candidate(
                finding, coverage_equivalent=True
            )
            finding = self._lifecycle.confirm_resolved_via_retest(finding)
            return finding, job

        if finding.state in {FindingState.RESOLVED, FindingState.RESOLVED_CANDIDATE}:
            finding = self._lifecycle.mark_regressed(finding)
        return finding, job
