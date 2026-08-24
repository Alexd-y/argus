"""Admin reports API — list, detail, generate, download, regenerate, share links.

Cross-tenant report console for super-admin operators; tenant-scoped read for
admin/operator roles. Reuses RBAC patterns from admin_findings.
"""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import Depends, HTTPException, Query, status
from sqlalchemy import String, asc, cast, desc, func, select

from src.api.routers.admin import require_admin, router
from src.api.routers.admin_findings import _admin_role_dep, _admin_tenant_dep
from src.api.schemas import (
    AdminReportDetailResponse,
    AdminReportDownloadResponse,
    AdminReportGenerateRequest,
    AdminReportGenerateResponse,
    AdminReportListItem,
    AdminReportListResponse,
    AdminReportRegenerateRequest,
    AdminReportRegenerateResponse,
    ReportShareLinkCreateRequest,
    ReportShareLinkResponse,
)
from src.core.datetime_format import format_created_at_iso_z
from src.db.models import Finding, Report, ReportObject, ReportShareLink
from src.db.session import async_session_factory, set_session_tenant

logger = logging.getLogger(__name__)

_ALLOWED_ROLES: frozenset[str] = frozenset({"operator", "admin", "super-admin"})
_TENANT_SCOPED_ROLES: frozenset[str] = frozenset({"operator", "admin"})


def _enforce_rbac(
    *,
    role: str,
    role_tenant: str | None,
    query_tenant: str | None,
) -> str | None:
    if role == "super-admin":
        return query_tenant
    if role in _TENANT_SCOPED_ROLES:
        if not query_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: tenant_id is required for this role",
            )
        if not role_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: X-Admin-Tenant header is required for this role",
            )
        if role_tenant != query_tenant:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Forbidden: tenant mismatch",
            )
        return query_tenant
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Forbidden",
    )


def _row_to_item(r: Report, severity_counts: dict[str, int] | None = None) -> AdminReportListItem:
    fmts = r.requested_formats
    if isinstance(fmts, dict):
        fmts = list(fmts.values()) if fmts else None
    tags = r.compliance_tags if isinstance(r.compliance_tags, list) else None
    return AdminReportListItem(
        id=r.id,
        tenant_id=r.tenant_id,
        scan_id=r.scan_id,
        target=r.target,
        tier=r.tier,
        generation_status=r.generation_status,
        requested_formats=fmts if isinstance(fmts, list) else None,
        version=r.version,
        parent_report_id=r.parent_report_id,
        assigned_to=r.assigned_to,
        compliance_tags=tags,
        severity_counts=severity_counts,
        created_at=format_created_at_iso_z(r.created_at),
    )


@router.get(
    "/reports",
    response_model=AdminReportListResponse,
    summary="List reports (admin, RBAC-scoped)",
)
async def admin_list_reports(
    tenant_id: UUID | None = Query(
        default=None,
        description="Tenant UUID; required for admin/operator roles",
    ),
    offset: int = Query(0, ge=0, le=100_000),
    limit: int = Query(50, ge=1, le=200),
    sort: str = Query(
        "created_at_desc",
        description="Sort: created_at_desc, created_at_asc, target_asc, target_desc",
    ),
    status_filter: str | None = Query(
        default=None,
        alias="status",
        description="Filter by generation_status",
    ),
    tier: str | None = Query(
        default=None,
        description="Filter by report tier (midgard, asgard, valhalla)",
    ),
    q: str | None = Query(
        default=None,
        max_length=200,
        description="Search by target (ILIKE)",
    ),
    since: datetime | None = Query(
        default=None,
        description="Inclusive lower bound on created_at",
    ),
    until: datetime | None = Query(
        default=None,
        description="Inclusive upper bound on created_at",
    ),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
) -> AdminReportListResponse:
    query_tid = str(tenant_id) if tenant_id is not None else None
    effective_tenant = _enforce_rbac(
        role=role,
        role_tenant=role_tenant,
        query_tenant=query_tid,
    )

    sort_map = {
        "created_at_desc": desc(Report.created_at),
        "created_at_asc": asc(Report.created_at),
        "target_desc": desc(Report.target),
        "target_asc": asc(Report.target),
    }
    order = sort_map.get(sort, desc(Report.created_at))

    filters: list = []
    if effective_tenant:
        filters.append(cast(Report.tenant_id, String) == effective_tenant)
    if status_filter and status_filter.strip():
        filters.append(Report.generation_status == status_filter.strip())
    if tier and tier.strip():
        filters.append(Report.tier == tier.strip())
    if q and q.strip():
        from src.api.routers.admin import _escape_ilike_pattern

        pattern = f"%{_escape_ilike_pattern(q.strip())}%"
        filters.append(Report.target.ilike(pattern, escape="\\"))
    if since is not None:
        filters.append(Report.created_at >= since)
    if until is not None:
        filters.append(Report.created_at <= until)

    async with async_session_factory() as session:
        if effective_tenant:
            await set_session_tenant(session, effective_tenant)

        count_stmt = select(func.count()).select_from(Report).where(*filters)
        total = int((await session.execute(count_stmt)).scalar_one())

        list_stmt = (
            select(Report)
            .where(*filters)
            .order_by(order)
            .offset(offset)
            .limit(limit)
        )
        rows = list((await session.execute(list_stmt)).scalars().all())

        report_ids = [r.id for r in rows]
        severity_map: dict[str, dict[str, int]] = {}
        if report_ids:
            sev_stmt = (
                select(Finding.report_id, Finding.severity, func.count())
                .where(cast(Finding.report_id, String).in_(report_ids))
                .group_by(Finding.report_id, Finding.severity)
            )
            sev_rows = (await session.execute(sev_stmt)).all()
            for rid, sev, cnt in sev_rows:
                rid_key = str(rid)
                if rid_key not in severity_map:
                    severity_map[rid_key] = {}
                severity_map[rid_key][sev.lower()] = cnt

    items = []
    for r in rows:
        sc = severity_map.get(r.id)
        items.append(_row_to_item(r, severity_counts=sc))

    has_more = (offset + len(items)) < total

    return AdminReportListResponse(
        reports=items,
        total=total,
        limit=limit,
        offset=offset,
        has_more=has_more,
    )


@router.get(
    "/reports/{report_id}",
    response_model=AdminReportDetailResponse,
    summary="Report detail (admin, RBAC-scoped)",
)
async def admin_get_report_detail(
    report_id: str,
    tenant_id: UUID = Query(..., description="Tenant UUID"),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
) -> AdminReportDetailResponse:
    query_tid = str(tenant_id)
    effective_tenant = _enforce_rbac(
        role=role,
        role_tenant=role_tenant,
        query_tenant=query_tid,
    )

    if not report_id or len(report_id) > 36:
        raise HTTPException(status_code=422, detail="Invalid report_id")

    async with async_session_factory() as session:
        await set_session_tenant(session, effective_tenant or query_tid)

        rr = await session.execute(
            select(Report).where(
                cast(Report.id, String) == report_id,
                cast(Report.tenant_id, String) == (effective_tenant or query_tid),
            )
        )
        report = rr.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        obj_rows = (
            await session.execute(
                select(ReportObject)
                .where(cast(ReportObject.report_id, String) == report_id)
                .order_by(asc(ReportObject.created_at))
            )
        ).scalars().all()

        finding_count_stmt = select(func.count()).select_from(Finding).where(
            cast(Finding.report_id, String) == report_id,
        )
        findings_total = int((await session.execute(finding_count_stmt)).scalar_one())

        severity_stmt = (
            select(Finding.severity, func.count())
            .where(cast(Finding.report_id, String) == report_id)
            .group_by(Finding.severity)
        )
        severity_rows = (await session.execute(severity_stmt)).all()
        severity_map: dict[str, int] = {row[0].lower(): row[1] for row in severity_rows}

    available_formats = list({o.format for o in obj_rows})

    fmts = report.requested_formats
    if isinstance(fmts, dict):
        fmts = list(fmts.values()) if fmts else None

    tags = report.compliance_tags if isinstance(report.compliance_tags, list) else None

    return AdminReportDetailResponse(
        id=report.id,
        tenant_id=report.tenant_id,
        scan_id=report.scan_id,
        target=report.target,
        tier=report.tier,
        generation_status=report.generation_status,
        requested_formats=fmts if isinstance(fmts, list) else None,
        created_at=format_created_at_iso_z(report.created_at),
        summary=severity_map if severity_map else None,
        technologies=report.technologies if isinstance(report.technologies, list) else None,
        available_formats=available_formats,
        findings_count=findings_total,
        last_error_message=report.last_error_message,
        version=report.version,
        parent_report_id=report.parent_report_id,
        assigned_to=report.assigned_to,
        compliance_tags=tags,
        severity_counts=severity_map if severity_map else None,
    )


@router.post(
    "/reports/generate",
    response_model=AdminReportGenerateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger report generation (admin)",
)
async def admin_generate_report(
    body: AdminReportGenerateRequest,
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
) -> AdminReportGenerateResponse:
    query_tid = str(body.tenant_id)
    effective_tenant = _enforce_rbac(
        role=role,
        role_tenant=role_tenant,
        query_tenant=query_tid,
    )

    async with async_session_factory() as session:
        await set_session_tenant(session, effective_tenant or query_tid)

        parent_version = 1
        if body.parent_report_id:
            pr = await session.execute(
                select(Report).where(cast(Report.id, String) == body.parent_report_id)
            )
            parent_report = pr.scalar_one_or_none()
            if parent_report:
                parent_version = (parent_report.version or 1) + 1

        report = Report(
            tenant_id=effective_tenant or query_tid,
            scan_id=body.scan_id,
            target=body.target or "",
            tier=body.tier,
            generation_status="pending",
            requested_formats=body.formats,
            assigned_to=body.assigned_to,
            compliance_tags=body.compliance_tags,
            version=parent_version if body.parent_report_id else 1,
            parent_report_id=body.parent_report_id,
        )
        if body.executive_summary:
            meta = report.report_metadata or {}
            meta["executive_summary"] = body.executive_summary
            report.report_metadata = meta

        session.add(report)
        await session.commit()
        await session.refresh(report)

    try:
        from src.tasks import generate_report_task

        generate_report_task.delay(
            str(report.id),
            str(report.tenant_id),
            str(report.scan_id) if report.scan_id else None,
        )
        logger.info(
            "admin.report_generate.task_queued",
            extra={
                "event": "argus.admin.report_generate.task_queued",
                "report_id": report.id,
            },
        )
    except Exception:
        logger.warning(
            "admin.report_generate.task_enqueue_failed",
            extra={
                "event": "argus.admin.report_generate.task_enqueue_failed",
                "report_id": report.id,
            },
            exc_info=True,
        )

    return AdminReportGenerateResponse(
        report_id=report.id,
        status="pending",
    )


@router.get(
    "/reports/{report_id}/download/{format}",
    response_model=AdminReportDownloadResponse,
    summary="Get presigned download URL for report artifact (admin)",
)
async def admin_download_report(
    report_id: str,
    format: str,
    tenant_id: UUID = Query(..., description="Tenant UUID"),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
) -> AdminReportDownloadResponse:
    query_tid = str(tenant_id)
    effective_tenant = _enforce_rbac(
        role=role,
        role_tenant=role_tenant,
        query_tenant=query_tid,
    )

    if not report_id or len(report_id) > 36:
        raise HTTPException(status_code=422, detail="Invalid report_id")

    async with async_session_factory() as session:
        await set_session_tenant(session, effective_tenant or query_tid)

        rr = await session.execute(
            select(Report).where(
                cast(Report.id, String) == report_id,
                cast(Report.tenant_id, String) == (effective_tenant or query_tid),
            )
        )
        report = rr.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        obj = (
            await session.execute(
                select(ReportObject).where(
                    cast(ReportObject.report_id, String) == report_id,
                    ReportObject.format == format,
                ).limit(1)
            )
        ).scalar_one_or_none()

        if not obj:
            raise HTTPException(
                status_code=404,
                detail=f"No artifact found for format '{format}'",
            )

    try:
        from src.storage.s3 import get_presigned_url_by_key

        download_url = get_presigned_url_by_key(obj.object_key)
    except Exception:
        download_url = None

    return AdminReportDownloadResponse(
        report_id=report_id,
        format=format,
        download_url=download_url,
        size_bytes=obj.size_bytes,
    )


@router.post(
    "/reports/{report_id}/regenerate",
    response_model=AdminReportRegenerateResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Regenerate report as a new version (admin)",
)
async def admin_regenerate_report(
    report_id: str,
    body: AdminReportRegenerateRequest | None = None,
    tenant_id: UUID = Query(..., description="Tenant UUID"),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
) -> AdminReportRegenerateResponse:
    query_tid = str(tenant_id)
    effective_tenant = _enforce_rbac(
        role=role,
        role_tenant=role_tenant,
        query_tenant=query_tid,
    )

    if not report_id or len(report_id) > 36:
        raise HTTPException(status_code=422, detail="Invalid report_id")

    body = body or AdminReportRegenerateRequest()

    async with async_session_factory() as session:
        await set_session_tenant(session, effective_tenant or query_tid)

        rr = await session.execute(
            select(Report).where(
                cast(Report.id, String) == report_id,
                cast(Report.tenant_id, String) == (effective_tenant or query_tid),
            )
        )
        old_report = rr.scalar_one_or_none()
        if not old_report:
            raise HTTPException(status_code=404, detail="Report not found")

        new_version = (old_report.version or 1) + 1
        formats = body.formats or (
            old_report.requested_formats
            if isinstance(old_report.requested_formats, list)
            else ["pdf", "html", "json"]
        )

        new_report = Report(
            tenant_id=effective_tenant or query_tid,
            scan_id=old_report.scan_id,
            target=old_report.target,
            tier=old_report.tier,
            generation_status="pending",
            requested_formats=formats,
            version=new_version,
            parent_report_id=old_report.id,
            assigned_to=body.assigned_to or old_report.assigned_to,
            compliance_tags=old_report.compliance_tags,
        )
        session.add(new_report)
        await session.commit()
        await session.refresh(new_report)

    try:
        from src.tasks import generate_report_task

        generate_report_task.delay(
            str(new_report.id),
            str(new_report.tenant_id),
            str(new_report.scan_id) if new_report.scan_id else None,
        )
    except Exception:
        logger.warning(
            "admin.report_regenerate.task_enqueue_failed",
            extra={"event": "argus.admin.report_regenerate.task_enqueue_failed", "report_id": new_report.id},
            exc_info=True,
        )

    return AdminReportRegenerateResponse(
        report_id=new_report.id,
        parent_report_id=old_report.id,
        version=new_version,
        status="pending",
    )


@router.post(
    "/reports/{report_id}/share-links",
    response_model=ReportShareLinkResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a time-limited share link for a report (admin)",
)
async def admin_create_share_link(
    report_id: str,
    body: ReportShareLinkCreateRequest,
    tenant_id: UUID = Query(..., description="Tenant UUID"),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
) -> ReportShareLinkResponse:
    query_tid = str(tenant_id)
    effective_tenant = _enforce_rbac(
        role=role,
        role_tenant=role_tenant,
        query_tenant=query_tid,
    )

    if not report_id or len(report_id) > 36:
        raise HTTPException(status_code=422, detail="Invalid report_id")

    token = secrets.token_urlsafe(48)[:64]
    expires_at = datetime.now(UTC) + timedelta(days=body.expires_in_days)

    async with async_session_factory() as session:
        await set_session_tenant(session, effective_tenant or query_tid)

        rr = await session.execute(
            select(Report).where(
                cast(Report.id, String) == report_id,
                cast(Report.tenant_id, String) == (effective_tenant or query_tid),
            )
        )
        report = rr.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        link = ReportShareLink(
            report_id=report.id,
            tenant_id=effective_tenant or query_tid,
            token=token,
            expires_at=expires_at,
            created_by=body.created_by,
        )
        session.add(link)
        await session.commit()
        await session.refresh(link)

    from src.core.config import settings

    share_url = f"{settings.base_url}/shared/reports/{token}" if hasattr(settings, "base_url") else None

    return ReportShareLinkResponse(
        id=link.id,
        report_id=link.report_id,
        token=link.token,
        share_url=share_url,
        expires_at=format_created_at_iso_z(link.expires_at),
        created_by=link.created_by,
        view_count=link.view_count,
    )


@router.get(
    "/reports/{report_id}/share-links",
    response_model=list[ReportShareLinkResponse],
    summary="List share links for a report (admin)",
)
async def admin_list_share_links(
    report_id: str,
    tenant_id: UUID = Query(..., description="Tenant UUID"),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
) -> list[ReportShareLinkResponse]:
    query_tid = str(tenant_id)
    effective_tenant = _enforce_rbac(
        role=role,
        role_tenant=role_tenant,
        query_tenant=query_tid,
    )

    if not report_id or len(report_id) > 36:
        raise HTTPException(status_code=422, detail="Invalid report_id")

    async with async_session_factory() as session:
        await set_session_tenant(session, effective_tenant or query_tid)

        rows = (
            await session.execute(
                select(ReportShareLink)
                .where(cast(ReportShareLink.report_id, String) == report_id)
                .order_by(desc(ReportShareLink.created_at))
            )
        ).scalars().all()

    return [
        ReportShareLinkResponse(
            id=link.id,
            report_id=link.report_id,
            token=link.token,
            share_url=None,
            expires_at=format_created_at_iso_z(link.expires_at),
            created_by=link.created_by,
            view_count=link.view_count,
        )
        for link in rows
    ]


@router.delete(
    "/reports/{report_id}/share-links/{link_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke a share link (admin)",
)
async def admin_delete_share_link(
    report_id: str,
    link_id: str,
    tenant_id: UUID = Query(..., description="Tenant UUID"),
    _: None = Depends(require_admin),
    role: str = Depends(_admin_role_dep),
    role_tenant: str | None = Depends(_admin_tenant_dep),
) -> None:
    query_tid = str(tenant_id)
    effective_tenant = _enforce_rbac(
        role=role,
        role_tenant=role_tenant,
        query_tenant=query_tid,
    )

    async with async_session_factory() as session:
        await set_session_tenant(session, effective_tenant or query_tid)

        link = (
            await session.execute(
                select(ReportShareLink).where(
                    cast(ReportShareLink.id, String) == link_id,
                    cast(ReportShareLink.report_id, String) == report_id,
                    cast(ReportShareLink.tenant_id, String) == (effective_tenant or query_tid),
                )
            )
        ).scalar_one_or_none()

        if not link:
            raise HTTPException(status_code=404, detail="Share link not found")

        await session.delete(link)
        await session.commit()


__all__ = [
    "admin_list_reports",
    "admin_get_report_detail",
    "admin_generate_report",
    "admin_download_report",
    "admin_regenerate_report",
    "admin_create_share_link",
    "admin_list_share_links",
    "admin_delete_share_link",
]
