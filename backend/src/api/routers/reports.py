"""Reports router — GET /reports, GET /reports/:id, GET /reports/:id/download."""

from __future__ import annotations

import contextlib
import io
from typing import Any
from urllib.parse import quote, urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import RedirectResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, StrictStr
from sqlalchemy import String, cast, select

from src.api.schemas import (
    Finding,
    ReportDetailResponse,
    ReportListResponse,
    ReportSummary,
)
from src.core.tenant import get_current_tenant_id
from src.db.models import Evidence as EvidenceModel
from src.db.models import Finding as FindingModel
from src.owasp_top10_2025 import parse_owasp_category
from src.reports.finding_metadata import (
    normalize_confidence,
    normalize_evidence_refs,
    normalize_evidence_type,
)
from src.db.models import PhaseOutput, Report, ReportObject, ScanTimeline
from src.db.models import Screenshot as ScreenshotModel
from src.db.session import async_session_factory, set_session_tenant
from src.reports.jinja_minimal_context import minimal_jinja_context_from_report_data
from src.reports.generators import (
    EvidenceEntry,
    PhaseOutputEntry,
    ReportData,
    ScreenshotEntry,
    TimelineEntry,
    VALHALLA_SECTIONS_CSV_FORMAT,
    build_report_data_from_db,
    generate_csv,
    generate_html,
    generate_json,
    generate_pdf,
    generate_valhalla_sections_csv,
)
from src.reports.report_bundle import ReportBundle, ReportFormat, ReportTier
from src.reports.report_pipeline import _upsert_report_object
from src.reports.report_service import (
    ReportGenerationError,
    ReportNotFoundError,
    ReportService,
)
from src.reports.tenant_pdf_format import resolve_tenant_pdf_archival_format
from src.reports.storage import download as storage_download
from src.reports.storage import exists as storage_exists
from src.reports.storage import get_presigned_url
from src.storage.s3 import download_by_key, get_presigned_url_by_key, upload_report_artifact

router = APIRouter(prefix="/reports", tags=["reports"])


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


@router.get("", response_model=list[ReportListResponse])
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
            findings_result = await session.execute(
                select(FindingModel).where(cast(FindingModel.report_id, String) == report.id)
            )
            findings = list(findings_result.scalars().all())
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


@router.get("/{report_id}", response_model=ReportDetailResponse)
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

        findings_result = await session.execute(
            select(FindingModel).where(cast(FindingModel.report_id, String) == report_id)
        )
        findings = list(findings_result.scalars().all())

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


async def _load_report_data(session, report: Report, findings: list[FindingModel]) -> ReportData:
    """Load full report data: timeline, phase outputs, evidence, screenshots."""
    scan_id = report.scan_id or report.id
    t_id = report.tenant_id or "default"

    timeline: list[TimelineEntry] = []
    phase_outputs: list[PhaseOutputEntry] = []
    evidence: list[EvidenceEntry] = []
    screenshots: list[ScreenshotEntry] = []

    if scan_id:
        tl_result = await session.execute(
            select(ScanTimeline)
            .where(cast(ScanTimeline.scan_id, String) == scan_id, cast(ScanTimeline.tenant_id, String) == t_id)
            .order_by(ScanTimeline.order_index, ScanTimeline.created_at)
        )
        for tl in tl_result.scalars().all():
            timeline.append(
                TimelineEntry(
                    phase=tl.phase or "",
                    order_index=tl.order_index or 0,
                    entry=tl.entry,
                    created_at=tl.created_at.isoformat() if tl.created_at else None,
                )
            )

        po_result = await session.execute(
            select(PhaseOutput)
            .where(cast(PhaseOutput.scan_id, String) == scan_id, cast(PhaseOutput.tenant_id, String) == t_id)
            .order_by(PhaseOutput.created_at)
        )
        for po in po_result.scalars().all():
            phase_outputs.append(
                PhaseOutputEntry(phase=po.phase or "", output_data=po.output_data)
            )

        ev_result = await session.execute(
            select(EvidenceModel).where(
                cast(EvidenceModel.scan_id, String) == scan_id, cast(EvidenceModel.tenant_id, String) == t_id
            )
        )
        for ev in ev_result.scalars().all():
            evidence.append(
                EvidenceEntry(
                    finding_id=ev.finding_id or "",
                    object_key=ev.object_key or "",
                    description=ev.description,
                )
            )

        ss_result = await session.execute(
            select(ScreenshotModel).where(
                cast(ScreenshotModel.scan_id, String) == scan_id, cast(ScreenshotModel.tenant_id, String) == t_id
            )
        )
        for ss in ss_result.scalars().all():
            screenshots.append(
                ScreenshotEntry(
                    object_key=ss.object_key or "",
                    url_or_email=ss.url_or_email,
                )
            )

    return build_report_data_from_db(
        report,
        findings,
        timeline=timeline,
        phase_outputs=phase_outputs,
        evidence=evidence,
        screenshots=screenshots,
    )


@router.get("/{report_id}/download", response_model=None)
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

        findings_result = await session.execute(
            select(FindingModel).where(cast(FindingModel.report_id, String) == report_id)
        )
        findings = list(findings_result.scalars().all())

        t_id = str(report.tenant_id or "default")
        scan_id = str(report.scan_id or report_id)
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

            cached = storage_exists(t_id, scan_id, "reports", filename)
            if cached:
                if redirect:
                    presigned_url = get_presigned_url(t_id, scan_id, "reports", filename)
                    if presigned_url:
                        return RedirectResponse(url=presigned_url, status_code=302)
                data = storage_download(t_id, scan_id, "reports", filename)
                if data:
                    fname = f"report-{report_id}.{fmt}"
                    return StreamingResponse(
                        io.BytesIO(data),
                        media_type=CONTENT_TYPES[fmt],
                        headers={"Content-Disposition": _attachment_content_disposition(fname)},
                    )

        report_data = await _load_report_data(session, report, findings)
        tier_str = str(report.tier or "midgard")
        jctx = minimal_jinja_context_from_report_data(report_data, tier_str)
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

        stored_key: str | None = None
        try:
            tier_str = str(report.tier or "midgard")
            stored_key = upload_report_artifact(
                t_id,
                scan_id,
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
                    scan_id=scan_id,
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
        400: {"description": "Invalid tier / format / missing identifiers"},
        404: {"description": "Scan or report not visible to the tenant"},
        503: {"description": "Generator unavailable (e.g. WeasyPrint missing for PDF)"},
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
    except ReportNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from None
    except ReportGenerationError:
        raise HTTPException(
            status_code=503,
            detail=f"Report generation unavailable for {req.format.value}",
        ) from None
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    return _bundle_response(bundle)
