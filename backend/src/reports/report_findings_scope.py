"""RPT-005 — Tenant-scoped finding queries for report APIs and exports."""

from __future__ import annotations

from sqlalchemy import String, and_, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.db.models import Finding as FindingModel


async def scan_id_hint_for_report_findings(
    session: AsyncSession,
    *,
    tenant_id: str,
    report_id: str,
    report_scan_id: str | None,
) -> str | None:
    """Effective scan_id to include findings with nullable ``Finding.report_id``."""
    if report_scan_id:
        return str(report_scan_id)
    r = await session.execute(
        select(FindingModel.scan_id).where(
            cast(FindingModel.tenant_id, String) == tenant_id,
            cast(FindingModel.report_id, String) == report_id,
        ).limit(1)
    )
    row = r.first()
    if row and row[0] is not None:
        return str(row[0])
    return None


async def load_findings_for_report(
    session: AsyncSession,
    *,
    tenant_id: str,
    report_id: str,
    scan_id: str | None,
) -> list[FindingModel]:
    """
    Findings tied to ``report_id`` OR scan-only rows (``report_id`` IS NULL) for the same scan.

    All rows are constrained by ``tenant_id`` (defense in depth with session RLS).
    """
    tenant_ok = cast(FindingModel.tenant_id, String) == tenant_id
    by_report = cast(FindingModel.report_id, String) == report_id
    if scan_id:
        stmt = (
            select(FindingModel)
            .where(
                tenant_ok,
                or_(
                    by_report,
                    and_(
                        FindingModel.report_id.is_(None),
                        cast(FindingModel.scan_id, String) == str(scan_id),
                    ),
                ),
            )
            .order_by(FindingModel.created_at.desc())
        )
    else:
        stmt = select(FindingModel).where(tenant_ok, by_report).order_by(
            FindingModel.created_at.desc()
        )
    result = await session.execute(stmt)
    return list(result.scalars().all())
