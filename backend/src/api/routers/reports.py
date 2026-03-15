"""Reports router — GET /reports, GET /reports/:id, GET /reports/:id/download."""

import io

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import RedirectResponse, StreamingResponse
from sqlalchemy import cast, select, String

from src.api.schemas import (
    Finding,
    ReportDetailResponse,
    ReportListResponse,
    ReportSummary,
)
from src.core.tenant import get_current_tenant_id
from src.db.models import Evidence as EvidenceModel
from src.db.models import Finding as FindingModel
from src.db.models import PhaseOutput
from src.db.models import Report
from src.db.models import ReportObject
from src.db.models import ScanTimeline
from src.db.models import Screenshot as ScreenshotModel
from src.db.session import async_session_factory, set_session_tenant
from src.reports.generators import (
    EvidenceEntry,
    PhaseOutputEntry,
    ReportData,
    ScreenshotEntry,
    TimelineEntry,
    build_report_data_from_db,
    generate_csv,
    generate_html,
    generate_json,
    generate_pdf,
)
from src.reports.storage import download as storage_download
from src.reports.storage import exists as storage_exists
from src.reports.storage import get_presigned_url
from src.reports.storage import upload

router = APIRouter(prefix="/reports", tags=["reports"])

VALID_FORMATS = {"pdf", "html", "json", "csv"}
CONTENT_TYPES = {
    "pdf": "application/pdf",
    "html": "text/html",
    "json": "application/json",
    "csv": "text/csv",
}


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
    format: str = Query("pdf", description="pdf|html|json|csv"),
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

        t_id = report.tenant_id or "default"
        scan_id = report.scan_id or report_id
        filename = f"report.{fmt}"

        use_cache = not regenerate
        if use_cache:
            cached = storage_exists(t_id, scan_id, "reports", filename)
            if cached:
                if redirect:
                    presigned_url = get_presigned_url(t_id, scan_id, "reports", filename)
                    if presigned_url:
                        return RedirectResponse(url=presigned_url, status_code=302)
                data = storage_download(t_id, scan_id, "reports", filename)
                if data:
                    return StreamingResponse(
                        io.BytesIO(data),
                        media_type=CONTENT_TYPES[fmt],
                        headers={"Content-Disposition": f'attachment; filename="report-{report_id}.{fmt}"'},
                    )

        report_data = await _load_report_data(session, report, findings)
        if fmt == "pdf":
            content = generate_pdf(report_data)
        elif fmt == "html":
            content = generate_html(report_data)
        elif fmt == "json":
            content = generate_json(report_data)
        else:
            content = generate_csv(report_data)

        try:
            stored_key = upload(
                t_id, scan_id, "reports", filename, content, content_type=CONTENT_TYPES[fmt]
            )
            if stored_key:
                ro = ReportObject(
                    tenant_id=t_id,
                    scan_id=scan_id,
                    report_id=report.id,
                    format=fmt,
                    object_key=stored_key,
                    size_bytes=len(content),
                )
                session.add(ro)
                try:
                    await session.commit()
                except Exception:
                    try:
                        await session.rollback()
                    except Exception:
                        pass
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid report path")

        if redirect:
            presigned_url = get_presigned_url(t_id, scan_id, "reports", filename)
            if presigned_url:
                return RedirectResponse(url=presigned_url, status_code=302)

    return StreamingResponse(
        io.BytesIO(content),
        media_type=CONTENT_TYPES[fmt],
        headers={"Content-Disposition": f'attachment; filename="report-{report_id}.{fmt}"'},
    )
