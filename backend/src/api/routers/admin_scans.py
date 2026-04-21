"""Admin scan history — GET /admin/scans, GET /admin/scans/{scan_id}.

List supports pagination and sort; detail returns tool run metrics and sanitized
error events (no stack traces in API responses).
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import Depends, HTTPException, Query
from sqlalchemy import String, asc, cast, desc, func, select

from src.api.routers.admin import require_admin, router
from src.api.schemas import (
    AdminScanDetailResponse,
    AdminScanErrorItemResponse,
    AdminScanListItemResponse,
    AdminScanListResponse,
    AdminScanSort,
    AdminScanToolMetricResponse,
)
from src.core.datetime_format import format_created_at_iso_z
from src.db.models import Scan, ScanEvent, Tenant, ToolRun
from src.db.session import async_session_factory, set_session_tenant

_STACK_HINTS: tuple[str, ...] = (
    "traceback",
    'file "',
    "\n  file \"",
    "stack trace",
)


def _sanitize_scan_error_message(raw: str | None) -> str:
    """Strip traceback-like content; keep a short operator-safe message."""
    if not raw:
        return "Error"
    s = raw.strip()
    if not s:
        return "Error"
    low = s.lower()
    if any(h in low for h in _STACK_HINTS):
        return "An error occurred."
    one_line = s.split("\n", 1)[0].strip()
    if len(one_line) > 400:
        return one_line[:397] + "..."
    return one_line


def _error_message_from_event(ev: ScanEvent) -> str:
    msg = ev.message
    data = ev.data
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, str) and err.strip():
            msg = err if not (msg and msg.strip()) else msg
    return _sanitize_scan_error_message(msg)


def _tool_duration_sec(started_at: datetime | None, finished_at: datetime | None) -> float | None:
    if started_at is not None and finished_at is not None:
        return max(0.0, (finished_at - started_at).total_seconds())
    return None


@router.get(
    "/scans",
    response_model=AdminScanListResponse,
    summary="List scans for a tenant (admin)",
)
async def admin_list_scans(
    tenant_id: UUID = Query(..., description="Tenant UUID"),
    offset: int = Query(0, ge=0, le=100_000),
    limit: int = Query(50, ge=1, le=200),
    sort: AdminScanSort = Query(
        "created_at_desc",
        description="Sort by scan created_at",
    ),
    status_filter: str | None = Query(
        None,
        alias="status",
        description="Optional exact status filter",
    ),
    _: None = Depends(require_admin),
) -> AdminScanListResponse:
    """Paginated scan history for admin consoles; tenant must exist."""
    tid = str(tenant_id)
    order = desc(Scan.created_at) if sort == "created_at_desc" else asc(Scan.created_at)

    async with async_session_factory() as session:
        await set_session_tenant(session, tid)

        tr = await session.execute(select(Tenant).where(cast(Tenant.id, String) == tid))
        if tr.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Tenant not found")

        filters = [cast(Scan.tenant_id, String) == tid]
        if status_filter and status_filter.strip():
            filters.append(Scan.status == status_filter.strip())

        count_stmt = select(func.count()).select_from(Scan).where(*filters)
        total = int((await session.execute(count_stmt)).scalar_one())

        list_stmt = (
            select(Scan)
            .where(*filters)
            .order_by(order)
            .offset(offset)
            .limit(limit)
        )
        lr = await session.execute(list_stmt)
        rows = list(lr.scalars().all())

    items = [
        AdminScanListItemResponse(
            id=s.id,
            status=s.status,
            progress=s.progress,
            phase=s.phase,
            target=s.target_url,
            created_at=format_created_at_iso_z(s.created_at),
            updated_at=format_created_at_iso_z(s.updated_at),
            scan_mode=str(getattr(s, "scan_mode", None) or "standard"),
        )
        for s in rows
    ]
    return AdminScanListResponse(
        scans=items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/scans/{scan_id}",
    response_model=AdminScanDetailResponse,
    summary="Scan drill-down: tool metrics + error summary (admin)",
)
async def admin_get_scan_detail(
    scan_id: str,
    tenant_id: UUID = Query(..., description="Tenant UUID"),
    _: None = Depends(require_admin),
) -> AdminScanDetailResponse:
    """Tool rows from ``tool_runs``; errors from ``scan_events`` (sanitized)."""
    tid = str(tenant_id)
    if not scan_id or len(scan_id) > 36:
        raise HTTPException(status_code=422, detail="Invalid scan_id")

    async with async_session_factory() as session:
        await set_session_tenant(session, tid)

        tr = await session.execute(select(Tenant).where(cast(Tenant.id, String) == tid))
        if tr.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Tenant not found")

        sr = await session.execute(
            select(Scan).where(
                cast(Scan.id, String) == scan_id,
                cast(Scan.tenant_id, String) == tid,
            )
        )
        scan = sr.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        tool_rows = (
            await session.execute(
                select(ToolRun)
                .where(
                    cast(ToolRun.scan_id, String) == scan_id,
                    cast(ToolRun.tenant_id, String) == tid,
                )
                .order_by(
                    asc(ToolRun.started_at).nulls_last(),
                    asc(ToolRun.finished_at).nulls_last(),
                    asc(ToolRun.id),
                )
            )
        ).scalars().all()

        ev_rows = (
            await session.execute(
                select(ScanEvent)
                .where(
                    cast(ScanEvent.scan_id, String) == scan_id,
                    cast(ScanEvent.tenant_id, String) == tid,
                    ScanEvent.event == "error",
                )
                .order_by(asc(ScanEvent.created_at), asc(ScanEvent.id))
            )
        ).scalars().all()

    tool_metrics = [
        AdminScanToolMetricResponse(
            tool_name=tr.tool_name,
            status=tr.status,
            duration_sec=_tool_duration_sec(tr.started_at, tr.finished_at),
            started_at=format_created_at_iso_z(tr.started_at) if tr.started_at else None,
            finished_at=format_created_at_iso_z(tr.finished_at) if tr.finished_at else None,
        )
        for tr in tool_rows
    ]
    error_summary = [
        AdminScanErrorItemResponse(
            at=format_created_at_iso_z(ev.created_at),
            phase=ev.phase,
            message=_error_message_from_event(ev),
        )
        for ev in ev_rows
    ]

    return AdminScanDetailResponse(
        id=scan.id,
        status=scan.status,
        progress=scan.progress,
        phase=scan.phase,
        target=scan.target_url,
        created_at=format_created_at_iso_z(scan.created_at),
        updated_at=format_created_at_iso_z(scan.updated_at),
        scan_mode=str(getattr(scan, "scan_mode", None) or "standard"),
        tool_metrics=tool_metrics,
        error_summary=error_summary,
    )


__all__ = ["admin_list_scans", "admin_get_scan_detail"]
