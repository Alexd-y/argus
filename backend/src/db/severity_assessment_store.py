"""Persistence adapter for :class:`~src.db.models.SeverityAssessment`.

Thin async layer bridging the ORM rows and the pure selection policy in
:mod:`src.findings.severity_assessment`. Kept separate so the policy stays
I/O-free and unit-testable, and so callers can record / read the effective
severity without duplicating the deterministic selection logic.
"""

from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import String, cast, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import SeverityAssessment
from src.findings.severity import SeverityBand
from src.findings.severity_assessment import (
    AssessmentRecord,
    conflicting_assessments,
    effective_band,
    select_effective_assessment,
)


def _to_record(row: SeverityAssessment) -> AssessmentRecord:
    evidence = row.evidence_ref if isinstance(row.evidence_ref, list) else []
    return AssessmentRecord(
        assessment_id=row.id,
        method=row.method,
        severity=row.severity,
        is_manual_override=bool(row.is_manual_override),
        created_at=row.created_at,
        policy_version=row.policy_version,
        source_ref=row.source_ref,
        supersedes=row.supersedes,
        rationale=row.rationale,
        override_author=row.override_author,
        override_reason=row.override_reason,
        evidence_ref=tuple(str(e) for e in evidence),
    )


async def load_assessments(
    session: AsyncSession, *, finding_id: str, tenant_id: str
) -> list[AssessmentRecord]:
    """Load all severity assessments for a finding as pure records."""
    rows = await session.execute(
        select(SeverityAssessment).where(
            cast(SeverityAssessment.finding_id, String) == finding_id,
            cast(SeverityAssessment.tenant_id, String) == tenant_id,
        )
    )
    return [_to_record(row) for row in rows.scalars()]


async def load_effective_band(
    session: AsyncSession, *, finding_id: str, tenant_id: str
) -> SeverityBand:
    """Return the deterministic effective severity band for a finding."""
    return effective_band(
        await load_assessments(session, finding_id=finding_id, tenant_id=tenant_id)
    )


async def record_assessment(
    session: AsyncSession,
    *,
    tenant_id: str,
    finding_id: str,
    method: str,
    severity: str,
    cvss_score: float | None = None,
    cvss_vector: str | None = None,
    source_ref: str | None = None,
    policy_version: str | None = None,
    rationale: str | None = None,
    evidence_ref: Sequence[str] | None = None,
    supersedes: str | None = None,
    is_manual_override: bool = False,
    override_author: str | None = None,
    override_reason: str | None = None,
) -> SeverityAssessment:
    """Persist a new severity opinion.

    A manual override must carry ``override_author`` and ``override_reason`` so
    the audit trail (who / when / why) is always complete. Conflicts against
    the currently-effective opinion are computed and stored on the new row.
    """
    if is_manual_override and not (override_author and override_reason):
        raise ValueError(
            "manual override requires override_author and override_reason"
        )

    existing = await load_assessments(
        session, finding_id=finding_id, tenant_id=tenant_id
    )
    row = SeverityAssessment(
        tenant_id=tenant_id,
        finding_id=finding_id,
        method=method,
        severity=severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        source_ref=source_ref,
        policy_version=policy_version,
        rationale=rationale,
        evidence_ref=list(evidence_ref) if evidence_ref else None,
        supersedes=supersedes,
        is_manual_override=is_manual_override,
        override_author=override_author,
        override_reason=override_reason,
    )

    # Record which existing opinions this one disagrees with (different band).
    incoming = _to_record(row)
    conflicts = [
        r.assessment_id
        for r in conflicting_assessments([*existing, incoming], effective=incoming)
    ]
    row.conflicts_with = conflicts or None

    session.add(row)
    await session.flush()
    return row


async def current_effective(
    session: AsyncSession, *, finding_id: str, tenant_id: str
) -> AssessmentRecord | None:
    """Return the effective :class:`AssessmentRecord` (or ``None``)."""
    return select_effective_assessment(
        await load_assessments(session, finding_id=finding_id, tenant_id=tenant_id)
    )


__all__ = [
    "current_effective",
    "load_assessments",
    "load_effective_band",
    "record_assessment",
]
