"""Scans router — POST /scans, GET /scans/:id, GET /scans/:id/events."""

import asyncio
import json
import time
import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import String, cast, desc, func, select, update
from sse_starlette.sse import EventSourceResponse

from src.api.schemas import (
    Finding,
    ReportGenerateAcceptedResponse,
    ReportGenerateAllAcceptedResponse,
    ReportGenerateAllRequest,
    ReportGenerateRequest,
    ScanArtifactItem,
    ScanCancelResponse,
    ScanCostApiResponse,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanDetailResponse,
    ScanListItemResponse,
    ScanOptions,
    ScanSkillCreateRequest,
    ScanSmartCreateRequest,
)
from src.core.datetime_format import format_created_at_iso_z
from src.core.observability import record_scan_started
from src.core.tenant import get_current_tenant_id
from src.db.models import Finding as FindingModel
from src.owasp_top10_2025 import parse_owasp_category
from src.db.models import Report as ReportModel
from src.db.models import Scan, ScanEvent, Target, Tenant
from src.db.session import async_session_factory, set_session_tenant
from src.llm.cost_tracker import ScanCostTracker
from src.reports.bundle_enqueue import enqueue_generate_all_bundle
from src.storage.s3 import RAW_ARTIFACT_PHASES, get_presigned_url_by_key, list_scan_artifacts
from src.tasks import generate_all_reports_task, generate_report_task, scan_phase_task

SSE_POLL_INTERVAL_SEC = 1.5
# Max wall time for GET /scans/{id}/events SSE before emitting "Event stream timeout" (30 minutes).
SSE_MAX_WAIT_SEC = 30 * 60

router = APIRouter(prefix="/scans", tags=["scans"])

_TERMINAL_SCAN_STATUSES = frozenset({"completed", "failed", "cancelled"})
_REPORT_TIERS = frozenset({"midgard", "asgard", "valhalla"})


def _effective_tenant_for_scan_create(body_tenant_id: str | None, tenant_id_header: str) -> str:
    """Match list_scans: header is context; optional body tenant_id must equal it or 403."""
    effective_tenant = tenant_id_header
    if body_tenant_id and body_tenant_id.strip():
        tid = body_tenant_id.strip()
        if tid != tenant_id_header:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="tenant_id must match authenticated tenant context",
            )
        effective_tenant = tid
    return effective_tenant


def _map_max_phases_to_scan_mode(max_phases: int) -> Literal["quick", "standard", "deep"]:
    if max_phases <= 2:
        return "quick"
    if max_phases <= 5:
        return "standard"
    return "deep"


async def _persist_scan_start(
    tenant_id: str,
    target: str,
    options_dict: dict[str, Any],
    scan_mode: Literal["quick", "standard", "deep"],
) -> str:
    """Insert tenant/target/scan and return scan_id."""
    scan_id = str(uuid.uuid4())
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        result = await session.execute(
            select(Tenant).where(cast(Tenant.id, String) == tenant_id)
        )
        if not result.scalar_one_or_none():
            session.add(Tenant(id=tenant_id, name="default"))
            await session.flush()

        target_row = Target(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            url=target,
        )
        session.add(target_row)
        await session.flush()

        scan = Scan(
            id=scan_id,
            tenant_id=tenant_id,
            target_id=target_row.id,
            target_url=target,
            status="queued",
            progress=0,
            phase="init",
            options=options_dict,
            scan_mode=scan_mode,
        )
        session.add(scan)
        await session.commit()
    return scan_id


@router.get("", response_model=list[ScanListItemResponse])
async def list_scans(
    status_filter: str | None = Query(
        None,
        alias="status",
        description="Filter by scan status",
    ),
    limit: int = Query(50, ge=1, le=200),
    tenant_id: str | None = Query(None, description="Must match X-Tenant-ID / default tenant"),
    tenant_id_header: str = Depends(get_current_tenant_id),
) -> list[ScanListItemResponse]:
    """List scans for tenant with optional status filter (HexStrike v4)."""
    effective_tenant = tenant_id_header
    if tenant_id and tenant_id.strip():
        tid = tenant_id.strip()
        if tid != tenant_id_header:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="tenant_id must match authenticated tenant context",
            )
        effective_tenant = tid

    async with async_session_factory() as session:
        await set_session_tenant(session, effective_tenant)
        q = (
            select(Scan)
            .where(cast(Scan.tenant_id, String) == effective_tenant)
            .order_by(desc(Scan.created_at))
            .limit(limit)
        )
        if status_filter and status_filter.strip():
            q = q.where(Scan.status == status_filter.strip())
        result = await session.execute(q)
        scans = list(result.scalars().all())
        return [
            ScanListItemResponse(
                id=s.id,
                status=s.status,
                progress=s.progress,
                phase=s.phase,
                target=s.target_url,
                created_at=format_created_at_iso_z(s.created_at),
                scan_mode=str(getattr(s, "scan_mode", None) or "standard"),
            )
            for s in scans
        ]


@router.post("/smart", response_model=ScanCreateResponse, status_code=201)
async def create_smart_scan(
    req: ScanSmartCreateRequest,
    tenant_id_header: str = Depends(get_current_tenant_id),
) -> ScanCreateResponse:
    """Enqueue scan from objective + phase budget; maps max_phases → scan_mode (v4)."""
    tenant_id = _effective_tenant_for_scan_create(req.tenant_id, tenant_id_header)
    scan_mode = _map_max_phases_to_scan_mode(req.max_phases)
    options_dict = ScanOptions().model_dump()
    options_dict["smart_objective"] = req.objective
    options_dict["max_phases"] = req.max_phases

    scan_id = await _persist_scan_start(tenant_id, req.target, options_dict, scan_mode)
    record_scan_started()
    scan_phase_task.delay(
        scan_id,
        tenant_id,
        req.target,
        options_dict,
    )
    return ScanCreateResponse(
        scan_id=scan_id,
        status="queued",
        message="Smart scan queued",
    )


@router.post("/skill", response_model=ScanCreateResponse, status_code=201)
async def create_skill_scan(
    req: ScanSkillCreateRequest,
    tenant_id_header: str = Depends(get_current_tenant_id),
) -> ScanCreateResponse:
    """Enqueue scan focused on a named skill (stored in options; v4)."""
    tenant_id = _effective_tenant_for_scan_create(req.tenant_id, tenant_id_header)
    options_dict = ScanOptions().model_dump()
    options_dict["skill_focus"] = req.skill
    scan_mode: Literal["quick", "standard", "deep"] = "deep"

    scan_id = await _persist_scan_start(tenant_id, req.target, options_dict, scan_mode)
    record_scan_started()
    scan_phase_task.delay(
        scan_id,
        tenant_id,
        req.target,
        options_dict,
    )
    return ScanCreateResponse(
        scan_id=scan_id,
        status="queued",
        message="Skill scan queued",
    )


@router.post("", response_model=ScanCreateResponse, status_code=201)
async def create_scan(
    req: ScanCreateRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ScanCreateResponse:
    """Create scan — persist to DB, run state machine in background."""
    scan_id = str(uuid.uuid4())
    options_dict = req.options.model_dump() if req.options else {}

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        # DB has VARCHAR(36) for id; ORM uses UUID — cast for comparison
        result = await session.execute(
            select(Tenant).where(cast(Tenant.id, String) == tenant_id)
        )
        if not result.scalar_one_or_none():
            tenant = Tenant(id=tenant_id, name="default")
            session.add(tenant)
            await session.flush()

        target = Target(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            url=req.target,
        )
        session.add(target)
        await session.flush()

        scan = Scan(
            id=scan_id,
            tenant_id=tenant_id,
            target_id=target.id,
            target_url=req.target,
            status="queued",
            progress=0,
            phase="init",
            options=options_dict,
            scan_mode=req.scan_mode,
        )
        session.add(scan)
        await session.commit()

    record_scan_started()
    scan_phase_task.delay(
        scan_id,
        tenant_id,
        req.target,
        options_dict,
    )

    return ScanCreateResponse(
        scan_id=scan_id,
        status="queued",
        message="Scan queued successfully",
    )


@router.get("/{scan_id}", response_model=ScanDetailResponse)
async def get_scan(
    scan_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ScanDetailResponse:
    """Get scan status from DB. Filtered by tenant (IDOR-safe)."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        # DB has VARCHAR(36) for id/tenant_id; ORM uses UUID — cast for comparison
        result = await session.execute(
            select(Scan).where(
                cast(Scan.id, String) == scan_id,
                cast(Scan.tenant_id, String) == tenant_id,
            )
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        return ScanDetailResponse(
            id=scan.id,
            status=scan.status,
            progress=scan.progress,
            phase=scan.phase,
            target=scan.target_url,
            created_at=format_created_at_iso_z(scan.created_at),
        )


@router.post("/{scan_id}/cancel", response_model=ScanCancelResponse)
async def cancel_scan(
    scan_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ScanCancelResponse:
    """Mark scan cancelled in DB. Worker revocation is not wired (use status for UX)."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        result = await session.execute(
            select(Scan).where(
                cast(Scan.id, String) == scan_id,
                cast(Scan.tenant_id, String) == tenant_id,
            )
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.status in _TERMINAL_SCAN_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scan already in terminal state",
            )
        await session.execute(
            update(Scan)
            .where(cast(Scan.id, String) == scan_id, cast(Scan.tenant_id, String) == tenant_id)
            .values(status="cancelled", phase="cancelled")
        )
        await session.commit()
    return ScanCancelResponse(
        scan_id=scan_id,
        status="cancelled",
        message="Scan marked cancelled",
    )


def _finding_to_schema(f: FindingModel) -> Finding:
    """Convert DB finding to API schema."""
    refs: list[str] = []
    if f.evidence_refs is not None:
        if isinstance(f.evidence_refs, list):
            refs = [str(x) for x in f.evidence_refs]
    return Finding(
        severity=f.severity,
        title=f.title,
        description=f.description or "",
        cwe=f.cwe,
        cvss=f.cvss,
        owasp_category=parse_owasp_category(f.owasp_category),
        proof_of_concept=f.proof_of_concept if isinstance(f.proof_of_concept, dict) else None,
        confidence=f.confidence or "likely",  # type: ignore[arg-type]
        evidence_type=f.evidence_type,  # type: ignore[arg-type]
        evidence_refs=refs,
        reproducible_steps=f.reproducible_steps,
        applicability_notes=f.applicability_notes,
        adversarial_score=f.adversarial_score,
        dedup_status=f.dedup_status,
    )


@router.get("/{scan_id}/findings/top", response_model=list[Finding])
async def get_scan_findings_top(
    scan_id: str,
    limit: int = Query(20, ge=1, le=100),
    tenant_id: str = Depends(get_current_tenant_id),
) -> list[Finding]:
    """Top findings by adversarial_score (HexStrike v4)."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        result = await session.execute(
            select(Scan).where(
                cast(Scan.id, String) == scan_id,
                cast(Scan.tenant_id, String) == tenant_id,
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Scan not found")
        result = await session.execute(
            select(FindingModel)
            .where(cast(FindingModel.scan_id, String) == scan_id)
            .order_by(desc(FindingModel.adversarial_score).nulls_last(), desc(FindingModel.created_at))
            .limit(limit)
        )
        findings = list(result.scalars().all())
        return [_finding_to_schema(f) for f in findings]


@router.get("/{scan_id}/findings", response_model=list[Finding])
async def get_scan_findings(
    scan_id: str,
    severity: str | None = Query(None, description="Filter by severity label"),
    validated_only: bool = Query(False, description="Only confidence=confirmed"),
    tenant_id: str = Depends(get_current_tenant_id),
) -> list[Finding]:
    """Get findings for a scan. Filtered by tenant (IDOR-safe)."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        # DB has VARCHAR(36) for id/tenant_id; ORM uses UUID — cast for comparison
        result = await session.execute(
            select(Scan).where(
                cast(Scan.id, String) == scan_id,
                cast(Scan.tenant_id, String) == tenant_id,
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Scan not found")
        fq = select(FindingModel).where(cast(FindingModel.scan_id, String) == scan_id)
        if severity and severity.strip():
            fq = fq.where(FindingModel.severity == severity.strip())
        if validated_only:
            fq = fq.where(FindingModel.confidence == "confirmed")
        result = await session.execute(fq)
        findings = list(result.scalars().all())
        return [_finding_to_schema(f) for f in findings]


@router.get("/{scan_id}/artifacts", response_model=list[ScanArtifactItem])
async def get_scan_artifacts(
    scan_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
    phase: str | None = Query(
        default=None,
        description="Limit to a phase folder (recon, threat_modeling, vuln_analysis, exploitation, post_exploitation)",
    ),
    raw_only: bool = Query(False, alias="raw"),
    presigned: bool = Query(False, description="Include presigned GET URL per object"),
) -> list[ScanArtifactItem]:
    """List MinIO/S3 objects for this scan. Tenant-scoped prefix; same auth as GET /scans/{id}."""
    if phase is not None and phase not in RAW_ARTIFACT_PHASES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid phase",
        )

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        result = await session.execute(
            select(Scan).where(
                cast(Scan.id, String) == scan_id,
                cast(Scan.tenant_id, String) == tenant_id,
            )
        )
        if not result.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Scan not found")

    try:
        rows = list_scan_artifacts(
            tenant_id,
            scan_id,
            phase=phase,
            raw_only=raw_only,
        )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="Invalid phase",
        ) from None

    if rows is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Storage unavailable",
        )

    out: list[ScanArtifactItem] = []
    for row in rows:
        url = None
        if presigned:
            url = get_presigned_url_by_key(row["key"])
        out.append(
            ScanArtifactItem(
                key=row["key"],
                size=row["size"],
                last_modified=format_created_at_iso_z(row["last_modified"]),
                content_type=row["content_type"],
                download_url=url,
            )
        )
    return out


@router.get("/{scan_id}/report", response_model=None)
async def get_scan_report(
    scan_id: str,
    fmt: str = Query(
        "pdf",
        alias="format",
        description="pdf|html|json|csv|valhalla_sections.csv",
    ),
    tier: str = Query("midgard", description="midgard|asgard|valhalla"),
    regenerate: bool = Query(False),
    redirect: bool = Query(False),
    tenant_id: str = Depends(get_current_tenant_id),
):
    """Scan-first report download (v4); reuses reports download pipeline."""
    tier_norm = tier.lower().strip()
    if tier_norm not in _REPORT_TIERS:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="Invalid tier")

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        sr = await session.execute(
            select(Scan).where(
                cast(Scan.id, String) == scan_id,
                cast(Scan.tenant_id, String) == tenant_id,
            )
        )
        if not sr.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Scan not found")

        rr = await session.execute(
            select(ReportModel)
            .where(
                cast(ReportModel.scan_id, String) == scan_id,
                cast(ReportModel.tenant_id, String) == tenant_id,
                ReportModel.tier == tier_norm,
            )
            .order_by(desc(ReportModel.created_at))
            .limit(1)
        )
        report = rr.scalar_one_or_none()

    if not report:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={
                "error": "report_not_found",
                "message": "No report row for this scan and tier; generate a report first.",
                "scan_id": scan_id,
                "tier": tier_norm,
                "generate": {
                    "method": "POST",
                    "path": f"/api/v1/scans/{scan_id}/reports/generate",
                    "alternate": f"/api/v1/scans/{scan_id}/reports/generate-all",
                },
            },
        )

    from src.api.routers.reports import download_report

    return await download_report(str(report.id), fmt, regenerate, redirect, tenant_id)


@router.get("/{scan_id}/cost", response_model=ScanCostApiResponse)
async def get_scan_cost(
    scan_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ScanCostApiResponse:
    """LLM cost summary: persisted cost_summary or empty ScanCostTracker breakdown."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        result = await session.execute(
            select(Scan).where(
                cast(Scan.id, String) == scan_id,
                cast(Scan.tenant_id, String) == tenant_id,
            )
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")
        raw = scan.cost_summary

    if isinstance(raw, dict) and raw.get("total_cost_usd") is not None:
        by_phase = raw.get("by_phase")
        return ScanCostApiResponse(
            scan_id=scan_id,
            total_cost_usd=float(raw.get("total_cost_usd", 0)),
            total_tokens=int(raw.get("total_tokens", 0)),
            total_calls=int(raw.get("total_calls", 0)),
            by_phase=by_phase if isinstance(by_phase, dict) else {},
            source="db_cost_summary",
        )

    bd = ScanCostTracker(scan_id).breakdown()
    return ScanCostApiResponse(
        scan_id=str(bd.get("scan_id") or scan_id),
        total_cost_usd=float(bd.get("total_cost_usd", 0)),
        total_tokens=int(bd.get("total_tokens", 0)),
        total_calls=int(bd.get("total_calls", 0)),
        by_phase=dict(bd.get("by_phase") or {}),
        source="tracker_empty",
    )


@router.get("/{scan_id}/memory-summary")
async def get_scan_memory_summary(
    scan_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> dict[str, Any]:
    """Aggregated scan context: findings, events, cost, technologies (from persisted fields)."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        result = await session.execute(
            select(Scan).where(
                cast(Scan.id, String) == scan_id,
                cast(Scan.tenant_id, String) == tenant_id,
            )
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        sev_rows = (
            await session.execute(
                select(FindingModel.severity, func.count())
                .where(cast(FindingModel.scan_id, String) == scan_id)
                .group_by(FindingModel.severity)
            )
        ).all()
        by_severity = {str(row[0]): int(row[1]) for row in sev_rows if row[0]}

        owasp_rows = (
            await session.execute(
                select(FindingModel.owasp_category, func.count())
                .where(cast(FindingModel.scan_id, String) == scan_id)
                .group_by(FindingModel.owasp_category)
            )
        ).all()
        by_owasp = {str(row[0]): int(row[1]) for row in owasp_rows if row[0]}

        cwe_rows = (
            await session.execute(
                select(FindingModel.cwe, func.count())
                .where(cast(FindingModel.scan_id, String) == scan_id)
                .group_by(FindingModel.cwe)
            )
        ).all()
        by_cwe = {str(row[0]): int(row[1]) for row in cwe_rows if row[0]}

        ev_rows = (
            await session.execute(
                select(ScanEvent.event, func.count())
                .where(cast(ScanEvent.scan_id, String) == scan_id)
                .group_by(ScanEvent.event)
            )
        ).all()
        by_event = {str(row[0]): int(row[1]) for row in ev_rows if row[0]}

    technologies: list[str] = []
    if isinstance(scan.options, dict):
        raw_tech = scan.options.get("technologies") or scan.options.get("technologies_detected")
        if isinstance(raw_tech, list):
            technologies = [str(x) for x in raw_tech]

    cost_summary: dict[str, Any] = scan.cost_summary if isinstance(scan.cost_summary, dict) else {}

    findings_total = sum(by_severity.values())

    return {
        "scan_id": scan_id,
        "status": scan.status,
        "phase": scan.phase,
        "progress": scan.progress,
        "target": scan.target_url,
        "findings": {"total": findings_total, "by_severity": by_severity},
        "by_owasp_category": by_owasp,
        "by_cwe": by_cwe,
        "events": by_event,
        "cost_summary": cost_summary,
        "technologies": technologies,
    }


@router.post(
    "/{scan_id}/reports/generate",
    response_model=ReportGenerateAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def generate_scan_report(
    scan_id: str,
    req: ReportGenerateRequest,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ReportGenerateAcceptedResponse:
    """Queue report generation for a scan — tenant-scoped (IDOR-safe). RPT-007."""
    report_id = str(uuid.uuid4())
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        result = await session.execute(
            select(Scan).where(
                cast(Scan.id, String) == scan_id,
                cast(Scan.tenant_id, String) == tenant_id,
            )
        )
        scan = result.scalar_one_or_none()
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

        row = ReportModel(
            id=report_id,
            tenant_id=tenant_id,
            scan_id=scan_id,
            target=scan.target_url,
            tier=req.type,
            generation_status="pending",
            requested_formats=list(req.formats),
            summary={},
            technologies=None,
        )
        session.add(row)
        await session.commit()

    async_result = generate_report_task.delay(
        report_id,
        tenant_id,
        scan_id,
        list(req.formats),
    )
    task_id = getattr(async_result, "id", None)
    return ReportGenerateAcceptedResponse(report_id=report_id, task_id=task_id)


@router.post(
    "/{scan_id}/reports/generate-all",
    response_model=ReportGenerateAllAcceptedResponse,
    status_code=status.HTTP_202_ACCEPTED,
)
async def generate_all_scan_reports(
    scan_id: str,
    request: Request,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ReportGenerateAllAcceptedResponse:
    """Queue generation for all tiers and selected formats (default: four formats × three tiers = 12 reports)."""
    raw: dict[str, Any] = {}
    try:
        body = await request.body()
        if body:
            parsed = json.loads(body)
            if not isinstance(parsed, dict):
                raise HTTPException(status_code=422, detail="Body must be a JSON object")
            raw = parsed
    except json.JSONDecodeError:
        raise HTTPException(status_code=422, detail="Invalid JSON body") from None

    try:
        req = ReportGenerateAllRequest.model_validate(raw)
    except ValidationError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=exc.errors(include_url=False, include_context=False),
        ) from None
    formats = req.resolved_formats()

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        bundle = await enqueue_generate_all_bundle(
            session,
            tenant_id,
            scan_id,
            formats,
            set_post_scan_idempotency_flag=False,
        )
        if not bundle:
            raise HTTPException(status_code=404, detail="Scan not found")
        bundle_id, report_ids = bundle
        await session.commit()

    async_result = generate_all_reports_task.delay(tenant_id, scan_id, bundle_id, report_ids)
    task_id = getattr(async_result, "id", None)
    return ReportGenerateAllAcceptedResponse(
        bundle_id=bundle_id,
        report_ids=report_ids,
        task_id=task_id,
        count=len(report_ids),
    )


# SSE event types per api-contracts/sse-polling.md
SSE_EVENT_TYPES = frozenset(
    {"phase_start", "phase_complete", "tool_run", "finding", "progress", "complete", "error"}
)

def _filter_sse_output_data(event_type: str, data: dict | None) -> dict | None:
    """
    Filter sensitive data from SSE payload (ARGUS-010).
    For phase_complete: keep only phase, progress, status, brief metadata (counts).
    Remove: payloads, credentials, internal paths, full findings/exploits/evidence.
    """
    if not data:
        return data
    if event_type != "phase_complete":
        return data
    safe: dict = {}
    if "assets" in data:
        safe["assets_count"] = len(data.get("assets") or [])
    if "subdomains" in data:
        safe["subdomains_count"] = len(data.get("subdomains") or [])
    if "ports" in data:
        safe["ports_count"] = len(data.get("ports") or [])
    if "findings" in data:
        safe["findings_count"] = len(data.get("findings") or [])
    if "exploits" in data:
        safe["exploits_count"] = len(data.get("exploits") or [])
    if "evidence" in data:
        safe["evidence_count"] = len(data.get("evidence") or [])
    if "report" in data:
        safe["report_ready"] = bool(data.get("report"))
    if "threat_model" in data:
        safe["threat_model_ready"] = bool(data.get("threat_model"))
    if "lateral" in data:
        safe["lateral_count"] = len(data.get("lateral") or [])
    if "persistence" in data:
        safe["persistence_count"] = len(data.get("persistence") or [])
    return safe if safe else None


def _build_sse_payload(ev: ScanEvent) -> dict:
    """Build SSE data payload per SSEEventPayload: `{ event, phase?, progress?, message?, data?, error? }`.
    phase_complete data is filtered to avoid leaking findings, exploits, evidence (ARGUS-010).
    For event=error, frontend reads payload.error."""
    payload: dict = {
        "event": ev.event,
    }
    if ev.phase is not None:
        payload["phase"] = ev.phase
    if ev.progress is not None:
        payload["progress"] = ev.progress
    if ev.message:
        payload["message"] = ev.message
    if ev.event == "error":
        payload["error"] = ev.message or (ev.data.get("error") if ev.data else None) or "Unknown error"
    filtered_data = _filter_sse_output_data(ev.event, ev.data)
    if filtered_data:
        payload["data"] = filtered_data
    return payload


def _format_sse_event(event: str, payload: dict) -> dict:
    """Format SSE event: event type + JSON data per SSEEventPayload."""
    return {"event": event, "data": json.dumps(payload)}


def _yield_error_event(message: str) -> dict:
    """Generic error event for SSE (no internal details leaked). Frontend reads payload.error."""
    return _format_sse_event(
        "error",
        {"event": "error", "message": message, "error": message, "progress": 0},
    )


@router.get("/{scan_id}/events")
async def get_scan_events(
    scan_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
):
    """SSE stream for scan events from DB. Content-Type: text/event-stream.
    Emits: phase_start, progress, complete, error. Polls scan_events until complete/failed."""
    async def event_generator():
        try:
            seen_event_ids: set[str] = set()
            started_at = time.monotonic()

            while True:
                async with async_session_factory() as session:
                    await set_session_tenant(session, tenant_id)
                    # DB has VARCHAR(36) for id/tenant_id; ORM uses UUID — cast for comparison
                    result = await session.execute(
                        select(Scan).where(
                            cast(Scan.id, String) == scan_id,
                            cast(Scan.tenant_id, String) == tenant_id,
                        )
                    )
                    scan = result.scalar_one_or_none()
                    if not scan:
                        yield _yield_error_event("Scan not found")
                        return

                    result = await session.execute(
                        select(ScanEvent)
                        .where(cast(ScanEvent.scan_id, String) == scan_id)
                        .order_by(ScanEvent.created_at)
                    )
                    events = list(result.scalars().all())

                if not events and not seen_event_ids:
                    yield _format_sse_event(
                        "init",
                        {"event": "init", "phase": "init", "progress": 0, "message": "Scan started"},
                    )
                    seen_event_ids.add("__init__")

                for ev in events:
                    if ev.id not in seen_event_ids:
                        seen_event_ids.add(ev.id)
                        payload = _build_sse_payload(ev)
                        yield _format_sse_event(ev.event, payload)

                if scan.status in ("completed", "failed"):
                    if scan.status == "completed":
                        if "complete" not in {e.event for e in events}:
                            yield _format_sse_event(
                                "complete",
                                {
                                    "event": "complete",
                                    "phase": scan.phase,
                                    "progress": 100,
                                    "message": "Scan completed",
                                },
                            )
                    else:
                        if "error" not in {e.event for e in events}:
                            yield _format_sse_event(
                                "error",
                                {
                                    "event": "error",
                                    "error": scan.phase or "Scan failed",
                                    "phase": scan.phase,
                                    "progress": scan.progress,
                                },
                            )
                    return

                elapsed = time.monotonic() - started_at
                if elapsed >= SSE_MAX_WAIT_SEC:
                    yield _format_sse_event(
                        "error",
                        {"event": "error", "error": "Event stream timeout"},
                    )
                    return

                await asyncio.sleep(SSE_POLL_INTERVAL_SEC)

        except Exception:
            yield _yield_error_event("Event stream error")
            return

    return EventSourceResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
