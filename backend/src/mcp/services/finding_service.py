"""Tenant-scoped finding operations consumed by MCP ``findings.*`` tools."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import String, cast, desc, func, select, update

from src.db.models import Finding as FindingModel
from src.db.models import FindingNote
from src.db.models import Scan
from src.db.session import async_session_factory, set_session_tenant
from src.mcp.exceptions import (
    ResourceNotFoundError,
    UpstreamServiceError,
    ValidationError,
)
from src.mcp.schemas.finding import (
    FindingDetail,
    FindingFilter,
    FindingListResult,
    FindingSummary,
    Severity,
)

_logger = logging.getLogger(__name__)


def _coerce_severity(raw: str | None) -> Severity:
    value = (raw or "info").lower().strip()
    try:
        return Severity(value)
    except ValueError:
        _logger.warning("mcp.finding.unknown_severity", extra={"raw": value})
        return Severity.INFO


def _ensure_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _row_to_summary(row: FindingModel) -> FindingSummary:
    return FindingSummary(
        finding_id=row.id,
        severity=_coerce_severity(row.severity),
        title=(row.title or "")[:500],
        cwe=row.cwe,
        owasp_category=row.owasp_category,
        confidence=row.confidence or "likely",
        false_positive=bool(row.false_positive),
        created_at=_ensure_aware(row.created_at),
    )


def _row_to_detail(row: FindingModel) -> FindingDetail:
    refs: tuple[str, ...] = ()
    raw_refs = row.evidence_refs
    if isinstance(raw_refs, list):
        refs = tuple(str(item) for item in raw_refs[:64])
    poc = row.proof_of_concept if isinstance(row.proof_of_concept, dict) else None
    return FindingDetail(
        finding_id=row.id,
        scan_id=row.scan_id,
        severity=_coerce_severity(row.severity),
        title=(row.title or "")[:500],
        description=(row.description or "")[:8_000] if row.description else None,
        cwe=row.cwe,
        cvss=float(row.cvss) if row.cvss is not None else None,
        owasp_category=row.owasp_category,
        confidence=row.confidence or "likely",
        evidence_type=row.evidence_type,
        proof_of_concept=poc,
        evidence_refs=refs,
        reproducible_steps=(
            (row.reproducible_steps or "")[:8_000] if row.reproducible_steps else None
        ),
        false_positive=bool(row.false_positive),
        false_positive_reason=row.false_positive_reason,
        created_at=_ensure_aware(row.created_at),
    )


async def list_findings(
    *,
    tenant_id: str,
    scan_id: str,
    filters: FindingFilter,
    limit: int,
    offset: int,
) -> FindingListResult:
    """Return paginated findings for a scan.

    Tenant isolation: an explicit ``tenant_id == :tenant`` predicate is
    appended even though RLS would already enforce it; defence in depth.
    """
    if not scan_id:
        raise ValidationError("scan_id is required.")
    try:
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            scan_check = await session.execute(
                select(Scan.id).where(
                    cast(Scan.id, String) == scan_id,
                    cast(Scan.tenant_id, String) == tenant_id,
                )
            )
            if scan_check.scalar_one_or_none() is None:
                raise ResourceNotFoundError(
                    f"Scan {scan_id!r} was not found in this tenant scope."
                )

            base = select(FindingModel).where(
                cast(FindingModel.scan_id, String) == scan_id,
                cast(FindingModel.tenant_id, String) == tenant_id,
            )
            if not filters.include_false_positive:
                base = base.where(FindingModel.false_positive.is_(False))
            if filters.severity is not None:
                base = base.where(FindingModel.severity == filters.severity.value)
            if filters.confidence is not None:
                base = base.where(FindingModel.confidence == filters.confidence)
            if filters.cwe is not None:
                base = base.where(FindingModel.cwe == filters.cwe)
            if filters.owasp_category is not None:
                base = base.where(FindingModel.owasp_category == filters.owasp_category)

            count_stmt = select(func.count()).select_from(base.subquery())
            total = (await session.execute(count_stmt)).scalar() or 0

            page_stmt = (
                base.order_by(desc(FindingModel.created_at)).limit(limit).offset(offset)
            )
            page_result = await session.execute(page_stmt)
            rows = list(page_result.scalars().all())

            items = tuple(_row_to_summary(row) for row in rows)
            next_offset = offset + len(items) if (offset + len(items)) < total else None
            return FindingListResult(
                items=items, total=int(total), next_offset=next_offset
            )
    except (ResourceNotFoundError, ValidationError):
        raise
    except Exception as exc:
        _logger.exception(
            "mcp.findings.list_failed",
            extra={"scan_id": scan_id, "tenant_id": tenant_id},
        )
        raise UpstreamServiceError(
            "Failed to read findings; please retry later."
        ) from exc


async def get_finding(*, tenant_id: str, finding_id: str) -> FindingDetail:
    """Return one finding by id (tenant-scoped)."""
    try:
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            row = (
                await session.execute(
                    select(FindingModel).where(
                        cast(FindingModel.id, String) == finding_id,
                        cast(FindingModel.tenant_id, String) == tenant_id,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                raise ResourceNotFoundError(
                    f"Finding {finding_id!r} was not found in this tenant scope."
                )
            return _row_to_detail(row)
    except ResourceNotFoundError:
        raise
    except Exception as exc:
        _logger.exception(
            "mcp.findings.get_failed",
            extra={"finding_id": finding_id, "tenant_id": tenant_id},
        )
        raise UpstreamServiceError(
            "Failed to read the finding; please retry later."
        ) from exc


async def mark_false_positive(
    *, tenant_id: str, finding_id: str, reason: str, actor: str
) -> bool:
    """Mark the finding as a false positive and append an operator note.

    Returns ``True`` when the row was updated, ``False`` when it was already
    flagged as a false positive (idempotent noop).
    """
    if not reason or len(reason.strip()) < 10:
        raise ValidationError("Reason must be at least 10 characters long.")
    try:
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            row = (
                await session.execute(
                    select(FindingModel).where(
                        cast(FindingModel.id, String) == finding_id,
                        cast(FindingModel.tenant_id, String) == tenant_id,
                    )
                )
            ).scalar_one_or_none()
            if row is None:
                raise ResourceNotFoundError(
                    f"Finding {finding_id!r} was not found in this tenant scope."
                )
            if row.false_positive:
                return False
            await session.execute(
                update(FindingModel)
                .where(
                    cast(FindingModel.id, String) == finding_id,
                    cast(FindingModel.tenant_id, String) == tenant_id,
                )
                .values(false_positive=True, false_positive_reason=reason)
            )
            note = FindingNote(
                finding_id=finding_id,
                tenant_id=tenant_id,
                author=f"mcp:{actor}"[:255],
                note=reason[:8_000],
            )
            session.add(note)
            await session.commit()
            return True
    except (ResourceNotFoundError, ValidationError):
        raise
    except Exception as exc:
        _logger.exception(
            "mcp.findings.mark_fp_failed",
            extra={"finding_id": finding_id, "tenant_id": tenant_id},
        )
        raise UpstreamServiceError(
            "Failed to update the finding; please retry later."
        ) from exc


__all__ = [
    "get_finding",
    "list_findings",
    "mark_false_positive",
]
