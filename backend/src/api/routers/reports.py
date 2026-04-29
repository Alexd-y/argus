"""Reports router — GET /reports, GET /reports/:id, GET /reports/:id/download."""

from __future__ import annotations

import contextlib
import io
import logging
from typing import Any
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, StrictStr
from sqlalchemy import String, cast, select

from src.api.schemas import (
    ErrorResponse,
    Finding,
    ReportDetailResponse,
    ReportListResponse,
    ReportSummary,
)
from src.core.tenant import get_current_tenant_id
from src.db.models import Finding as FindingModel
from src.owasp_top10_2025 import parse_owasp_category
from src.reports.finding_metadata import (
    normalize_confidence,
    normalize_evidence_refs,
    normalize_evidence_type,
)
from src.db.models import Report, ReportObject
from src.db.session import async_session_factory, set_session_tenant
from src.reports.generators import (
    VALHALLA_SECTIONS_CSV_FORMAT,
    generate_csv,
    generate_html,
    generate_json,
    generate_pdf,
    generate_valhalla_sections_csv,
)
from src.reports.report_bundle import ReportBundle, ReportFormat, ReportTier
from src.reports.report_findings_scope import (
    load_findings_for_report,
    scan_id_hint_for_report_findings,
)
from src.reports.report_pipeline import _upsert_report_object, resolve_scan_id_for_report
from src.reports.report_service import (
    ReportGenerationError,
    ReportNotFoundError,
    ReportService,
)
from src.reports.tenant_pdf_format import resolve_tenant_pdf_archival_format
from src.reports.storage import download as storage_download
from src.services.reporting import build_report_export_payload
from src.reports.storage import exists as storage_exists
from src.reports.storage import get_presigned_url
from src.storage.s3 import download_by_key, get_presigned_url_by_key, upload_report_artifact

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/reports", tags=["reports"])

# OpenAPI: ошибки для путей под contract_http_exception_handler — JSON { error, code?, details? }
_REPORT_HTTP_ERROR_RESPONSES: dict[int | str, dict[str, Any]] = {
    400: {"model": ErrorResponse, "description": "Bad request"},
    404: {"model": ErrorResponse, "description": "Not found"},
    422: {"model": ErrorResponse, "description": "Validation failed"},
    503: {"model": ErrorResponse, "description": "Service unavailable"},
}


def _hostname_from_target_string(value: str) -> str | None:
    """Parse hostname from a full URL or a bare host (for list filter fallback)."""
    raw = (value or "").strip()
    if not raw:
        return None
    if "://" not in raw:
        raw = f"https://{raw}"
    try:
        host = urlparse(raw).hostname
        return host.lower() if host else None
    except Exception:
        return None


VALID_FORMATS = {"pdf", "html", "json", "csv", VALHALLA_SECTIONS_CSV_FORMAT}
CONTENT_TYPES = {
    "pdf": "application/pdf",
    "html": "text/html; charset=utf-8",
    "json": "application/json; charset=utf-8",
    "csv": "text/csv; charset=utf-8",
    VALHALLA_SECTIONS_CSV_FORMAT: "text/csv; charset=utf-8",
}


def _serialize_requested_formats(raw: Any) -> list[str] | None:
    """Normalize Report.requested_formats JSONB (list or {formats: [...]}) for API responses."""
    if raw is None:
        return None
    if isinstance(raw, list):
        return [str(x) for x in raw]
    if isinstance(raw, dict):
        inner = raw.get("formats")
        if isinstance(inner, list):
            return [str(x) for x in inner]
    return None


def _attachment_content_disposition(filename: str) -> str:
    """
    RFC 6266 attachment header: ASCII fallback + RFC 5987 filename* for UTF-8 (RPT-009).
    """
    safe_ascii = filename.encode("ascii", "replace").decode("ascii").replace('"', "_")
    encoded = quote(filename, safe="")
    return f'attachment; filename="{safe_ascii}"; filename*=UTF-8\'\'{encoded}'


def _report_to_summary(report: Report) -> ReportSummary:
    """Build ReportSummary from Report.summary JSONB."""
    s = dict(report.summary or {})
    s.pop("ai_insights", None)
    return ReportSummary(
        critical=int(s.get("critical", 0)),
        high=int(s.get("high", 0)),
        medium=int(s.get("medium", 0)),
        low=int(s.get("low", 0)),
        info=int(s.get("info", 0)),
        technologies=s.get("technologies", []) or [],
        sslIssues=int(s.get("sslIssues", 0)),
        headerIssues=int(s.get("headerIssues", 0)),
        leaksFound=bool(s.get("leaksFound", False)),
    )


def _get_ai_insights(report: Report) -> list[str]:
    """Extract ai_insights from Report.summary JSONB."""
    s = report.summary or {}
    ai = s.get("ai_insights")
    if isinstance(ai, list):
        return [str(x) for x in ai]
    if ai:
        return [str(ai)]
    return []


def _findings_to_schema(findings: list[FindingModel]) -> list[Finding]:
    """Convert DB findings to API schema."""
    return [
        Finding(
            severity=f.severity,
            title=f.title,
            description=f.description or "",
            cwe=f.cwe,
            cvss=f.cvss,
            owasp_category=parse_owasp_category(f.owasp_category),
            proof_of_concept=f.proof_of_concept if isinstance(f.proof_of_concept, dict) else None,
            confidence=normalize_confidence(getattr(f, "confidence", None), default="likely"),
            evidence_type=normalize_evidence_type(getattr(f, "evidence_type", None)),
            evidence_refs=normalize_evidence_refs(getattr(f, "evidence_refs", None)),
            reproducible_steps=getattr(f, "reproducible_steps", None),
            applicability_notes=getattr(f, "applicability_notes", None),
        )
        for f in findings
    ]


@router.get(
    "",
    response_model=list[ReportListResponse],
    responses={
        **_REPORT_HTTP_ERROR_RESPONSES,
    },
)
async def list_reports(
    target: str | None = Query(None, description="Filter by target URL"),
    tenant_id: str = Depends(get_current_tenant_id),
) -> list[ReportListResponse]:
    """List reports. Filtered by tenant (IDOR-safe). Optional filter by target."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        q = select(Report).where(cast(Report.tenant_id, String) == tenant_id).order_by(Report.created_at.desc())
        if target:
            q = q.where(Report.target == target)
        result = await session.execute(q)
        reports = list(result.scalars().all())

        # Frontend historically passed host-only (?target=example.com) while Report.target is full URL.
        if target and not reports:
            want_host = _hostname_from_target_string(target)
            if want_host:
                q2 = (
                    select(Report)
                    .where(cast(Report.tenant_id, String) == tenant_id)
                    .order_by(Report.created_at.desc())
                )
                result2 = await session.execute(q2)
                reports = [
                    r
                    for r in result2.scalars().all()
                    if _hostname_from_target_string(r.target or "") == want_host
                ]

        if not reports:
            return []

        out = []
        for report in reports:
            scan_for = await scan_id_hint_for_report_findings(
                session,
                tenant_id=tenant_id,
                report_id=report.id,
                report_scan_id=report.scan_id,
            )
            findings = await load_findings_for_report(
                session,
                tenant_id=tenant_id,
                report_id=report.id,
                scan_id=scan_for,
            )
            summary = _report_to_summary(report)
            out.append(
                ReportListResponse(
                    report_id=report.id,
                    target=report.target,
                    summary=summary,
                    findings=_findings_to_schema(findings),
                    technologies=report.technologies or [],
                    generation_status=report.generation_status or "ready",
                    tier=report.tier or "midgard",
                    requested_formats=_serialize_requested_formats(report.requested_formats),
                )
            )
        return out


@router.get(
    "/{report_id}",
    response_model=ReportDetailResponse,
    responses={
        404: _REPORT_HTTP_ERROR_RESPONSES[404],
        422: _REPORT_HTTP_ERROR_RESPONSES[422],
    },
)
async def get_report(
    report_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ReportDetailResponse:
    """Get full report by ID. Filtered by tenant (IDOR-safe)."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        result = await session.execute(
            select(Report).where(cast(Report.id, String) == report_id, cast(Report.tenant_id, String) == tenant_id)
        )
        report = result.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        scan_for = await scan_id_hint_for_report_findings(
            session,
            tenant_id=tenant_id,
            report_id=report_id,
            report_scan_id=report.scan_id,
        )
        findings = await load_findings_for_report(
            session,
            tenant_id=tenant_id,
            report_id=report_id,
            scan_id=scan_for,
        )

        return ReportDetailResponse(
            report_id=report.id,
            target=report.target,
            summary=_report_to_summary(report),
            findings=_findings_to_schema(findings),
            technologies=report.technologies or [],
            created_at=report.created_at.isoformat() if report.created_at else None,
            scan_id=report.scan_id,
            generation_status=report.generation_status or "ready",
            tier=report.tier or "midgard",
            requested_formats=_serialize_requested_formats(report.requested_formats),
        )


@router.get(
    "/{report_id}/download",
    response_model=None,
    responses={
        400: _REPORT_HTTP_ERROR_RESPONSES[400],
        404: _REPORT_HTTP_ERROR_RESPONSES[404],
        503: _REPORT_HTTP_ERROR_RESPONSES[503],
    },
)
async def download_report(
    report_id: str,
    format: str = Query(
        "pdf",
        description="pdf|html|json|csv|valhalla_sections.csv (Valhalla tier only)",
    ),
    regenerate: bool = Query(False, description="Force regeneration, skip cache"),
    redirect: bool = Query(False, description="Redirect to presigned URL instead of streaming"),
    tenant_id: str = Depends(get_current_tenant_id),
):
    """Download report in specified format. Filtered by tenant (IDOR-safe)."""
    fmt = format.lower()
    if fmt not in VALID_FORMATS:
        raise HTTPException(status_code=400, detail=f"Invalid format. Use: {', '.join(VALID_FORMATS)}")

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        result = await session.execute(
            select(Report).where(cast(Report.id, String) == report_id, cast(Report.tenant_id, String) == tenant_id)
        )
        report = result.scalar_one_or_none()
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        t_id = str(report.tenant_id or "default")
        effective_scan_id = await resolve_scan_id_for_report(
            session, tenant_id, report_id, report, scan_id_hint=None
        )
        filename = f"report.{fmt}"

        use_cache = not regenerate
        if use_cache:
            ro_result = await session.execute(
                select(ReportObject).where(
                    cast(ReportObject.report_id, String) == report_id,
                    ReportObject.format == fmt,
                    cast(ReportObject.tenant_id, String) == t_id,
                )
            )
            ro = ro_result.scalar_one_or_none()
            if ro and ro.object_key:
                if redirect:
                    presigned_url = get_presigned_url_by_key(ro.object_key)
                    if presigned_url:
                        return RedirectResponse(url=presigned_url, status_code=302)
                data = download_by_key(ro.object_key)
                if data:
                    fname = f"report-{report_id}.{fmt}"
                    return StreamingResponse(
                        io.BytesIO(data),
                        media_type=CONTENT_TYPES[fmt],
                        headers={"Content-Disposition": _attachment_content_disposition(fname)},
                    )

            cached = (
                storage_exists(t_id, effective_scan_id, "reports", filename)
                if effective_scan_id
                else False
            )
            if cached:
                if redirect:
                    presigned_url = get_presigned_url(t_id, effective_scan_id, "reports", filename)
                    if presigned_url:
                        return RedirectResponse(url=presigned_url, status_code=302)
                data = storage_download(t_id, effective_scan_id, "reports", filename)
                if data:
                    fname = f"report-{report_id}.{fmt}"
                    return StreamingResponse(
                        io.BytesIO(data),
                        media_type=CONTENT_TYPES[fmt],
                        headers={"Content-Disposition": _attachment_content_disposition(fname)},
                    )

        if not effective_scan_id:
            raise HTTPException(
                status_code=400,
                detail="Report export is unavailable: no scan linked to this report.",
            )

        tier_str = str(report.tier or "midgard")
        stored_key: str | None = None
        try:
            report_data, jctx = await build_report_export_payload(
                session,
                tenant_id=tenant_id,
                report_id=report_id,
                scan_id=effective_scan_id,
                tier=report.tier,
                include_minio=True,
                sync_ai=True,
            )
            if fmt == VALHALLA_SECTIONS_CSV_FORMAT:
                if tier_str != "valhalla":
                    raise HTTPException(
                        status_code=400,
                        detail="valhalla_sections.csv is only available for valhalla tier reports",
                    )
                content = generate_valhalla_sections_csv(report_data, jinja_context=jctx)
            elif fmt == "pdf":
                tenant_pdf_format = await resolve_tenant_pdf_archival_format(
                    session, t_id
                )
                content = generate_pdf(
                    report_data,
                    jinja_context=jctx,
                    tier=tier_str,
                    pdf_archival_format=tenant_pdf_format,
                )
            elif fmt == "html":
                content = generate_html(report_data, jinja_context=jctx, tier=tier_str)
            elif fmt == "json":
                content = generate_json(report_data, jinja_context=jctx)
            else:
                content = generate_csv(report_data, jinja_context=jctx)

            try:
                stored_key = upload_report_artifact(
                    t_id,
                    effective_scan_id,
                    tier_str,
                    str(report.id),
                    fmt,
                    content,
                    content_type=CONTENT_TYPES[fmt],
                )
                if stored_key:
                    await _upsert_report_object(
                        session,
                        tenant_id=t_id,
                        scan_id=effective_scan_id,
                        report_id=str(report.id),
                        fmt=fmt,
                        object_key=stored_key,
                        size_bytes=len(content),
                    )
                    try:
                        await session.commit()
                    except Exception:
                        with contextlib.suppress(Exception):
                            await session.rollback()
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid report path") from None
        except HTTPException:
            raise
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid report path") from None
        except Exception:
            logger.exception(
                "report_download_export_failed",
                extra={"report_id": report_id, "tenant_id": tenant_id},
            )
            raise HTTPException(
                status_code=503,
                detail="Report export is temporarily unavailable.",
            ) from None

        if redirect and stored_key:
            presigned_url = get_presigned_url_by_key(stored_key)
            if presigned_url:
                return RedirectResponse(url=presigned_url, status_code=302)

    fname = f"report-{report_id}.{fmt}"
    return StreamingResponse(
        io.BytesIO(content),
        media_type=CONTENT_TYPES[fmt],
        headers={"Content-Disposition": _attachment_content_disposition(fname)},
    )


# ---------------------------------------------------------------------------
# ARG-024 — Unified ReportService entry point
# ---------------------------------------------------------------------------


class GenerateReportRequest(BaseModel):
    """Request body for ``POST /reports/generate`` (ARG-024)."""

    model_config = ConfigDict(extra="forbid")

    scan_id: StrictStr | None = Field(default=None, max_length=128)
    report_id: StrictStr | None = Field(default=None, max_length=128)
    tier: ReportTier = ReportTier.MIDGARD
    format: ReportFormat = ReportFormat.JSON


class GenerateReportMetadata(BaseModel):
    """Inline metadata returned alongside the bundle (X-Argus-* headers mirror)."""

    model_config = ConfigDict(extra="forbid")

    tier: StrictStr
    format: StrictStr
    sha256: StrictStr
    size_bytes: int
    mime_type: StrictStr


def _bundle_response(bundle: ReportBundle) -> StreamingResponse:
    """Wrap a :class:`ReportBundle` in a streaming HTTP response with headers."""
    fname = bundle.filename(stem=f"report-{bundle.tier.value}")
    headers = {
        "Content-Disposition": _attachment_content_disposition(fname),
        "Content-Length": str(bundle.size_bytes),
        "X-Argus-Report-Tier": bundle.tier.value,
        "X-Argus-Report-Format": bundle.format.value,
        "X-Argus-Report-SHA256": bundle.sha256,
        "X-Argus-Report-Size-Bytes": str(bundle.size_bytes),
    }
    return StreamingResponse(
        io.BytesIO(bundle.content),
        media_type=bundle.mime_type,
        headers=headers,
    )


@router.post(
    "/generate",
    response_class=StreamingResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate a tier × format report bundle (ARG-024 ReportService)",
    responses={
        200: {"description": "Report bundle (binary)"},
        400: _REPORT_HTTP_ERROR_RESPONSES[400],
        404: _REPORT_HTTP_ERROR_RESPONSES[404],
        422: _REPORT_HTTP_ERROR_RESPONSES[422],
        503: _REPORT_HTTP_ERROR_RESPONSES[503],
    },
)
async def generate_report_bundle(
    req: GenerateReportRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> StreamingResponse:
    """Generate a ``ReportBundle`` for ``(scan_id|report_id, tier, format)``.

    Tenant-scoped via ``X-Tenant-ID`` header (or default tenant when unset).
    Returns the report bytes inline (``Content-Disposition: attachment``)
    plus ``X-Argus-Report-*`` metadata headers — including a SHA-256 the
    caller MUST verify before trusting the artifact (tamper evidence).
    """
    if not req.scan_id and not req.report_id:
        raise HTTPException(
            status_code=400,
            detail="At least one of scan_id or report_id must be provided",
        )

    service = ReportService()
    try:
        bundle = await service.generate(
            tenant_id=tenant_id,
            scan_id=req.scan_id,
            report_id=req.report_id,
            tier=req.tier,
            fmt=req.format,
        )
    except ReportNotFoundError:  # _load_report_data when no Report row for this tenant/ids
        raise HTTPException(status_code=404, detail="Report not found") from None
    except ReportGenerationError as exc:
        logger.warning(
            "report_bundle_generation_failed",
            extra={
                "event": "report_bundle_generation_failed",
                "format": req.format.value,
                "tier": req.tier.value,
            },
            exc_info=exc,
        )
        raise HTTPException(
            status_code=503,
            detail=f"Report generation unavailable for {req.format.value}",
        ) from None
    except ValueError as exc:
        # Client-facing validation only — no tracebacks (exception handlers strip internals).
        logger.warning(
            "report_bundle_bad_request",
            extra={"event": "report_bundle_bad_request"},
            exc_info=exc,
        )
        raise HTTPException(status_code=400, detail=str(exc)) from None

    return _bundle_response(bundle)
