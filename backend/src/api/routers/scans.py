"""Scans router — POST /scans, GET /scans/:id, GET /scans/:id/events."""

import asyncio
import io
import json
import logging
import time
import uuid
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError
from sqlalchemy import String, asc, cast, desc, func, select, update
from sse_starlette.sse import EventSourceResponse

from src.api.routers.reports import _attachment_content_disposition
from src.api.schemas import (
    Finding,
    QuickBudgetView,
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
    ScanFindingsStatisticsResponse,
    ScanListItemResponse,
    ScanOptions,
    ScanPlanResponse,
    ScanSkillCreateRequest,
    ScanSmartCreateRequest,
    ScanTimelineEventItem,
    ScanTimelineResponse,
)
from src.celery_app import app as celery_app
from src.core.config import settings
from src.core.datetime_format import format_created_at_iso_z
from src.core.observability import record_scan_started
from src.core.tenant import get_current_tenant_id
from src.db.models import Finding as FindingModel
from src.db.models import Report as ReportModel
from src.db.models import ReportObject
from src.db.models import Scan, ScanEvent, Target, Tenant
from src.db.session import async_session_factory, set_session_tenant
from src.execution_mode.mode import ExecutionMode
from src.llm.cost_tracker import ScanCostTracker
from src.nuclei.profile_compiler import default_profile_id_for_mode
from src.owasp_top10_2025 import parse_owasp_category
from src.policy.scan_queue import try_pick_queued_scan
from src.profiles import (
    ConflictingProfileFieldsError,
    detect_legacy_conflict,
    resolve_scan_profile,
)
from src.profiles.lab_preflight import preflight_lab_lease
from src.quick.cancellation import propagate_scan_cancellation
from src.quick.create import (
    PLAN_NOT_APPLICABLE,
    QuickCreateError,
    assert_execution_mode_payload,
    budget_view_from_mapping,
    error_detail,
    overlay_quick_options,
    parse_requested_execution_mode,
    persist_quick_rows,
    resolve_quick_runtime,
)
from src.quick.models import QuickScanConfigRow, QuickScanPlanRow
from src.quick.resolver import UnknownQuickProfileError
from src.reports.bundle_enqueue import enqueue_generate_all_bundle
from src.reports.generators import build_report_data_from_scan_findings
from src.reports.junit_generator import generate_junit
from src.reports.report_bundle import ReportFormat, mime_type_for
from src.reports.sarif_generator import generate_sarif
from src.storage.s3 import (
    RAW_ARTIFACT_PHASES,
    get_presigned_url_by_key,
    list_scan_artifacts,
)
from src.tasks import generate_all_reports_task, generate_report_task

SSE_POLL_INTERVAL_SEC = 1.5
SSE_KEEPALIVE_INTERVAL_SEC = 15  # Emit keepalive comments to prevent proxy timeout
# Max wall time for GET /scans/{id}/events SSE before emitting "Event stream timeout" (30 minutes).
SSE_MAX_WAIT_SEC = 30 * 60

router = APIRouter(prefix="/scans", tags=["scans"])
logger = logging.getLogger(__name__)

_TERMINAL_SCAN_STATUSES = frozenset({"completed", "failed", "cancelled"})
_REPORT_TIERS = frozenset({"midgard", "asgard", "valhalla"})
_SEVERITY_RISK_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 7.0,
    "medium": 4.0,
    "low": 2.0,
    "info": 1.0,
    "informational": 1.0,
}


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


ScanCreateMode = Literal["quick", "standard", "deep", "lab"]


def _map_max_phases_to_scan_mode(max_phases: int) -> Literal["quick", "standard", "deep"]:
    if max_phases <= 2:
        return "quick"
    if max_phases <= 5:
        return "standard"
    return "deep"


def _sync_scan_depth_options(
    options_dict: dict[str, Any],
    scan_mode: ScanCreateMode,
    *,
    target: str | None = None,
) -> dict[str, Any]:
    """Keep legacy options.scanType and canonical scan_mode aligned for workers."""
    options_dict = dict(options_dict)
    options_dict["scan_mode"] = scan_mode
    options_dict["scanType"] = scan_mode
    if scan_mode == "lab":
        options_dict.setdefault("active_injection_mode", "lab")
        options_dict.setdefault("intentional_vulnerable_lab", True)
        options_dict.setdefault("lab_profile", "intentional_vulnerable_lab")
        flags = options_dict.get("scan_approval_flags")
        if not isinstance(flags, dict):
            flags = {}
        for tool in ("sqlmap", "commix", "hydra", "medusa", "dalfox", "xsstrike", "ffuf", "nuclei", "wfuzz", "gobuster", "feroxbuster", "testssl", "sslscan", "whatweb", "nikto", "theharvester", "gospider", "parsero", "wpscan", "joomscan", "droopescan"):
            flags.setdefault(tool, True)
        options_dict["scan_approval_flags"] = flags
        allowlist = _merge_lab_allowed_targets(
            options_dict.get("lab_allowed_targets"),
            options_dict.get("argus_lab_allowed_targets"),
            target,
        )
        options_dict["lab_allowed_targets"] = allowlist
        options_dict["argus_lab_allowed_targets"] = ",".join(allowlist)
    return options_dict


def _merge_lab_allowed_targets(*values: Any) -> list[str]:
    """Build a conservative per-scan lab allowlist from UI/env-shaped values."""
    out: list[str] = []

    def add(raw: Any) -> None:
        if raw is None:
            return
        if isinstance(raw, (list, tuple, set)):
            for item in raw:
                add(item)
            return
        text = str(raw).strip()
        if not text or text.lower() in {"true", "false", "none", "null"}:
            return
        if "," in text:
            for part in text.split(","):
                add(part)
            return
        candidate = _normalize_lab_allowed_target(text)
        if candidate and candidate not in out:
            out.append(candidate)

    for value in values:
        add(value)
    add("localhost")
    add("127.0.0.1")
    return out


def _normalize_lab_allowed_target(value: str) -> str:
    raw = value.strip().rstrip("/")
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://{raw}")
    if not parsed.netloc:
        return raw
    if raw.startswith(("http://", "https://")):
        return f"{parsed.scheme}://{parsed.netloc}".rstrip("/")
    return parsed.netloc


def _quick_http_error(exc: QuickCreateError | UnknownQuickProfileError) -> HTTPException:
    code = getattr(exc, "code", "quick_create_error")
    return HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=error_detail(str(exc) if str(exc) else code, code),
    )


def _budget_view(raw: dict[str, Any] | None) -> QuickBudgetView | None:
    projected = budget_view_from_mapping(raw)
    if not projected:
        return None
    return QuickBudgetView.model_validate(projected)


def _budget_from_scan(scan: Scan) -> QuickBudgetView | None:
    options = scan.options if isinstance(scan.options, dict) else {}
    raw = options.get("quick_budget") if isinstance(options.get("quick_budget"), dict) else None
    view = _budget_view(raw if isinstance(raw, dict) else None)
    if view is not None:
        return view
    if getattr(scan, "quick_profile", None) and isinstance(options.get("quick"), dict):
        wall = options["quick"].get("wall_clock_budget_seconds")
        if wall is not None:
            return QuickBudgetView(
                wall_clock_budget_seconds=int(wall),
                ai_budget_seconds=options["quick"].get("ai_budget_seconds"),
                reserve_for_validation_percent=options["quick"].get(
                    "reserve_for_validation_percent"
                ),
            )
    return None


def _plan_response_from_row(scan_id: str, row: QuickScanPlanRow) -> ScanPlanResponse:
    budget_raw = row.budget if isinstance(row.budget, dict) else {}
    budget = _budget_view(budget_raw)
    if budget is None:
        budget = QuickBudgetView(wall_clock_budget_seconds=1)
    profile = "balanced"
    if isinstance(budget_raw, dict) and budget_raw.get("profile"):
        profile = str(budget_raw.get("profile"))
    return ScanPlanResponse(
        scan_id=scan_id,
        mode="quick",
        profile=profile if profile in {"compact", "balanced", "extended"} else "balanced",
        plan_version=int(row.plan_version),
        deadline_at=format_created_at_iso_z(row.deadline_at),
        budget=budget,
        stages=list(row.stages) if isinstance(row.stages, list) else [],
        tasks=list(row.tasks) if isinstance(row.tasks, list) else [],
        fallbacks=list(row.fallbacks) if isinstance(row.fallbacks, list) else [],
        coverage_intent=list(row.coverage_intent) if isinstance(row.coverage_intent, list) else [],
        assumptions=list(row.assumptions) if isinstance(row.assumptions, list) else [],
        prompt_version=row.prompt_version,
        model_route=row.model_route,
        revision_reason=row.revision_reason,
    )


async def _persist_scan_start(
    tenant_id: str,
    target: str,
    options_dict: dict[str, Any],
    scan_mode: ScanCreateMode,
) -> str:
    """Insert tenant/target/scan and return scan_id.

    The scan is created with ``status="queued"``. After commit the queue
    processor is notified so it can start the scan immediately if a slot
    is available.
    """
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
    """List scans for tenant with optional status filter (ARGUS v4)."""
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
                email=getattr(s, "email", None),
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
    options_dict = _sync_scan_depth_options(options_dict, scan_mode, target=req.target)
    options_dict["smart_objective"] = req.objective
    options_dict["max_phases"] = req.max_phases

    scan_id = await _persist_scan_start(tenant_id, req.target, options_dict, scan_mode)
    record_scan_started()
    await try_pick_queued_scan(tenant_id)
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
    options_dict = _sync_scan_depth_options(options_dict, scan_mode, target=req.target)

    scan_id = await _persist_scan_start(tenant_id, req.target, options_dict, scan_mode)
    record_scan_started()
    await try_pick_queued_scan(tenant_id)
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
    """Create scan — persist to DB, queue for execution."""
    scan_id = str(uuid.uuid4())
    options_dict = req.options.model_dump() if req.options else {}

    scan_mode: ScanCreateMode = req.scan_mode
    deadline_at: datetime | None = None
    quick_profile: str | None = None
    quick_config = None
    quick_budget = None
    resolved_profile = None
    profile_version: str | None = None
    engagement_id: str | None = None
    lab_lease_id: str | None = None

    # Canonical Profile Resolver path (Design §5). When scan_profile is provided
    # it is the single source of truth; legacy scan_mode/execution_mode are
    # deprecated and must not conflict with the resolved profile.
    if req.scan_profile is not None:
        legacy_scan_mode = req.scan_mode if "scan_mode" in req.model_fields_set else None
        legacy_execution_mode = (
            req.execution_mode if "execution_mode" in req.model_fields_set else None
        )
        conflicts = detect_legacy_conflict(
            req.scan_profile,
            legacy_scan_mode=legacy_scan_mode,
            legacy_execution_mode=legacy_execution_mode,
        )
        if conflicts:
            raise ConflictingProfileFieldsError(
                "scan_profile conflicts with legacy scan_mode/execution_mode fields",
                details={"conflicting_fields": conflicts, "scan_profile": req.scan_profile},
            )
        quick_hint = req.quick.profile if req.quick is not None else None
        resolved_profile = resolve_scan_profile(req.scan_profile, quick_profile=quick_hint)
        execution_mode = resolved_profile.execution_mode
        scan_mode = resolved_profile.scan_mode  # type: ignore[assignment]
        profile_version = resolved_profile.profile_version
        engagement_id = (req.engagement_id or "").strip() or None
        lab_lease_id = (req.lab_lease_id or "").strip() or None
    else:
        try:
            execution_mode = parse_requested_execution_mode(req.execution_mode)
        except QuickCreateError as exc:
            raise _quick_http_error(exc) from exc

    try:
        assert_execution_mode_payload(
            execution_mode,
            has_quick_payload=req.quick is not None,
        )
    except QuickCreateError as exc:
        raise _quick_http_error(exc) from exc

    if execution_mode is ExecutionMode.QUICK:
        scan_mode = "quick"
        options_dict = _sync_scan_depth_options(options_dict, scan_mode, target=req.target)
        quick_payload = req.quick.model_dump(exclude_none=True) if req.quick is not None else None
        started_at = datetime.now(UTC)
        try:
            quick_config, quick_budget, deadline_at = resolve_quick_runtime(
                tenant_id=tenant_id,
                quick_payload=quick_payload,
                started_at=started_at,
            )
        except UnknownQuickProfileError as exc:
            raise _quick_http_error(exc) from exc
        except QuickCreateError as exc:
            raise _quick_http_error(exc) from exc
        quick_profile = quick_config.profile.value
        options_dict = overlay_quick_options(
            options_dict,
            config=quick_config,
            budget=quick_budget,
            deadline_at=deadline_at,
        )
    else:
        options_dict = _sync_scan_depth_options(options_dict, scan_mode, target=req.target)
        if execution_mode is not ExecutionMode.PRODUCTION:
            options_dict["execution_mode"] = execution_mode.value
        if engagement_id:
            options_dict["engagement_id"] = engagement_id
        if lab_lease_id:
            options_dict["lab_lease_id"] = lab_lease_id

    # Resolved nuclei profile is always populated for observability/reporting.
    nuclei_profile = (
        resolved_profile.nuclei_profile
        if resolved_profile is not None
        else default_profile_id_for_mode(execution_mode)
    )

    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)

        # deep profile → server-side LAB lease boundary validation (Design §7).
        # Raises ArgusProfileError (rendered by the profile error handler).
        if resolved_profile is not None and resolved_profile.requires_lab_lease:
            await preflight_lab_lease(
                session,
                tenant_id=tenant_id,
                engagement_id=engagement_id,
                lab_lease_id=lab_lease_id,
                target=req.target,
            )

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
            scan_mode=scan_mode,
            execution_mode=execution_mode.value,
            deadline_at=deadline_at,
            quick_profile=quick_profile,
            email=req.email,
            scan_profile=(
                resolved_profile.external_profile.value if resolved_profile is not None else None
            ),
            resolved_scan_mode=scan_mode,
            nuclei_profile=nuclei_profile,
            engagement_id=engagement_id,
            lab_lease_id=lab_lease_id,
            profile_version=profile_version,
        )
        session.add(scan)
        if quick_config is not None and quick_budget is not None and deadline_at is not None:
            persist_quick_rows(
                session,
                tenant_id=tenant_id,
                scan_id=scan_id,
                config=quick_config,
                budget=quick_budget,
                deadline_at=deadline_at,
            )
        await session.commit()

    record_scan_started()
    await try_pick_queued_scan(tenant_id)

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

        em_raw = getattr(scan, "execution_mode", None)
        execution_mode = (
            em_raw
            if isinstance(em_raw, str) and em_raw in {"production", "lab_unrestricted", "quick"}
            else "production"
        )
        deadline_raw = getattr(scan, "deadline_at", None)
        profile_raw = getattr(scan, "quick_profile", None)
        scan_profile_raw = getattr(scan, "scan_profile", None)
        return ScanDetailResponse(
            id=scan.id,
            status=scan.status,
            progress=scan.progress,
            phase=scan.phase,
            target=scan.target_url,
            email=scan.email,
            created_at=format_created_at_iso_z(scan.created_at),
            scan_profile=(
                scan_profile_raw
                if isinstance(scan_profile_raw, str)
                and scan_profile_raw in {"quick", "light", "deep"}
                else None
            ),
            resolved_scan_mode=getattr(scan, "resolved_scan_mode", None)
            or str(getattr(scan, "scan_mode", None) or "") or None,
            nuclei_profile=getattr(scan, "nuclei_profile", None),
            engagement_id=getattr(scan, "engagement_id", None),
            lab_lease_id=getattr(scan, "lab_lease_id", None),
            profile_version=getattr(scan, "profile_version", None),
            report_snapshot_version=getattr(scan, "report_snapshot_version", None),
            execution_mode=execution_mode,
            deadline_at=(
                format_created_at_iso_z(deadline_raw)
                if isinstance(deadline_raw, datetime)
                else None
            ),
            quick_profile=(
                profile_raw
                if isinstance(profile_raw, str)
                and profile_raw in {"compact", "balanced", "extended"}
                else None
            ),
            budget=_budget_from_scan(scan),
            stage=scan.phase if execution_mode == ExecutionMode.QUICK.value else None,
        )


@router.get("/{scan_id}/plan", response_model=ScanPlanResponse)
async def get_scan_plan(
    scan_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ScanPlanResponse:
    """Return the latest Quick plan. 404 plan_not_applicable for non-quick scans."""
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
        mode_raw = getattr(scan, "execution_mode", None)
        mode = mode_raw if isinstance(mode_raw, str) else ExecutionMode.PRODUCTION.value
        if mode != ExecutionMode.QUICK.value:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=error_detail(
                    "Plan is only available for Quick execution mode",
                    PLAN_NOT_APPLICABLE,
                ),
            )
        plan_result = await session.execute(
            select(QuickScanPlanRow)
            .where(
                cast(QuickScanPlanRow.scan_id, String) == scan_id,
                cast(QuickScanPlanRow.tenant_id, String) == tenant_id,
            )
            .order_by(desc(QuickScanPlanRow.plan_version))
            .limit(1)
        )
        plan_row = plan_result.scalar_one_or_none()
        profile = str(getattr(scan, "quick_profile", None) or "balanced")
        if profile not in {"compact", "balanced", "extended"}:
            profile = "balanced"
        if plan_row is None:
            config_result = await session.execute(
                select(QuickScanConfigRow).where(
                    cast(QuickScanConfigRow.scan_id, String) == scan_id,
                    cast(QuickScanConfigRow.tenant_id, String) == tenant_id,
                )
            )
            config_row = config_result.scalar_one_or_none()
            deadline = getattr(scan, "deadline_at", None)
            budget = _budget_from_scan(scan)
            if budget is None:
                budget = QuickBudgetView(
                    wall_clock_budget_seconds=int(
                        getattr(config_row, "wall_clock_budget_seconds", None) or 1
                    ),
                    ai_budget_seconds=getattr(config_row, "ai_budget_seconds", None),
                    reserve_for_validation_percent=getattr(
                        config_row, "reserve_for_validation_percent", None
                    ),
                )
            return ScanPlanResponse(
                scan_id=scan_id,
                mode="quick",
                profile=profile,  # type: ignore[arg-type]
                plan_version=0,
                deadline_at=format_created_at_iso_z(deadline),
                budget=budget,
                stages=["discovery", "fingerprint", "test", "verify", "triage", "report"],
                tasks=[],
                fallbacks=["deterministic_planner"],
                coverage_intent=[],
                assumptions=["awaiting_fingerprint"],
            )
        response = _plan_response_from_row(scan_id, plan_row)
        return response.model_copy(update={"profile": profile})


@router.post("/{scan_id}/cancel", response_model=ScanCancelResponse)
async def cancel_scan(
    scan_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ScanCancelResponse:
    """Mark scan cancelled and revoke Celery/sandbox workers. Raw evidence is kept."""
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
        try:
            await propagate_scan_cancellation(
                scan_id=scan_id,
                tenant_id=tenant_id,
                reason="api_cancel",
                session=session,
                celery_app=celery_app,
            )
        except Exception:  # noqa: BLE001 — cancel response must succeed even if revoke fails
            logger.warning(
                "scan_cancel_revoke_failed",
                extra={"event": "scan_cancel_revoke_failed", "scan_id": scan_id},
            )
    return ScanCancelResponse(
        scan_id=scan_id,
        status="cancelled",
        message="Scan marked cancelled",
    )


def _finding_to_schema(f: FindingModel) -> Finding:
    """Convert DB finding to API schema."""
    refs: list[str] = []
    if f.evidence_refs is not None and isinstance(f.evidence_refs, list):
        refs = [str(x) for x in f.evidence_refs]
    return Finding(
        finding_id=str(f.id) if f.id is not None else None,
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
    """Top findings by adversarial_score (ARGUS v4)."""
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


@router.get("/{scan_id}/findings/statistics", response_model=ScanFindingsStatisticsResponse)
async def get_scan_findings_statistics(
    scan_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ScanFindingsStatisticsResponse:
    """Aggregated finding counts, CWE inventory, and weighted risk (excludes false positives)."""
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

        conf_rows = (
            await session.execute(
                select(FindingModel.confidence, func.count())
                .where(cast(FindingModel.scan_id, String) == scan_id)
                .group_by(FindingModel.confidence)
            )
        ).all()
        by_confidence = {str(row[0]): int(row[1]) for row in conf_rows if row[0]}

        cwe_rows = await session.execute(
            select(FindingModel.cwe)
            .where(
                cast(FindingModel.scan_id, String) == scan_id,
                FindingModel.cwe.isnot(None),
                FindingModel.cwe != "",
            )
            .distinct()
        )
        unique_cwes = sorted({str(r[0]) for r in cwe_rows.all() if r[0]})

        val_r = await session.execute(
            select(func.count())
            .select_from(FindingModel)
            .where(
                cast(FindingModel.scan_id, String) == scan_id,
                FindingModel.confidence == "confirmed",
            )
        )
        validated = int(val_r.scalar_one() or 0)

        fp_r = await session.execute(
            select(func.count())
            .select_from(FindingModel)
            .where(
                cast(FindingModel.scan_id, String) == scan_id,
                FindingModel.false_positive.is_(True),
            )
        )
        false_positives = int(fp_r.scalar_one() or 0)

        risk_rows = (
            await session.execute(
                select(FindingModel.severity, func.count())
                .where(
                    cast(FindingModel.scan_id, String) == scan_id,
                    FindingModel.false_positive.is_(False),
                )
                .group_by(FindingModel.severity)
            )
        ).all()
        risk_score = 0.0
        for row in risk_rows:
            if not row[0]:
                continue
            label = str(row[0]).strip().lower()
            w = _SEVERITY_RISK_WEIGHTS.get(label, 0.5)
            risk_score += w * int(row[1])

    return ScanFindingsStatisticsResponse(
        scan_id=scan_id,
        by_severity=by_severity,
        by_owasp=by_owasp,
        by_confidence=by_confidence,
        unique_cwes=unique_cwes,
        validated=validated,
        false_positives=false_positives,
        risk_score=round(risk_score, 4),
    )


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


async def _stream_scan_findings_export(
    scan_id: str,
    export_fmt: Literal["sarif", "junit"],
    tenant_id: str,
    severity: str | None,
    validated_only: bool,
) -> StreamingResponse:
    """SARIF 2.1.0 or JUnit XML for scan findings; requires tenant opt-in."""
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
            raise HTTPException(status_code=404, detail="Not found")
        tr = await session.execute(
            select(Tenant.exports_sarif_junit_enabled).where(
                cast(Tenant.id, String) == tenant_id,
            )
        )
        if not tr.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="Not found")
        fq = select(FindingModel).where(cast(FindingModel.scan_id, String) == scan_id)
        if severity and severity.strip():
            fq = fq.where(FindingModel.severity == severity.strip())
        if validated_only:
            fq = fq.where(FindingModel.confidence == "confirmed")
        result = await session.execute(fq)
        findings = list(result.scalars().all())
    report_data = build_report_data_from_scan_findings(scan, findings)
    if export_fmt == "sarif":
        body = generate_sarif(report_data, tool_version=settings.version)
        media = mime_type_for(ReportFormat.SARIF)
        fname = f"findings-{scan_id}.sarif"
    else:
        body = generate_junit(report_data)
        media = mime_type_for(ReportFormat.JUNIT)
        fname = f"findings-{scan_id}.junit.xml"
    return StreamingResponse(
        io.BytesIO(body),
        media_type=media,
        headers={"Content-Disposition": _attachment_content_disposition(fname)},
    )


@router.get(
    "/{scan_id}/findings/export",
    response_class=StreamingResponse,
    responses={
        200: {
            "content": {
                "application/sarif+json": {},
                "application/xml": {},
            },
            "description": "SARIF 2.1.0 or JUnit XML (see format query).",
        },
        404: {"description": "Not found (or export not enabled for tenant)."},
    },
    summary="Export findings as SARIF or JUnit",
    description=(
        "Requires ``tenants.exports_sarif_junit_enabled`` for the caller's tenant "
        "(set via admin API). Otherwise returns 404 without distinguishing reason. "
        "Output excludes raw PoC bodies and storage paths (see report generators)."
    ),
)
async def export_scan_findings(
    scan_id: str,
    export_format: Literal["sarif", "junit"] = Query(
        ...,
        alias="format",
        description="Export format: sarif (SARIF 2.1.0 JSON) or junit (JUnit XML).",
    ),
    severity: str | None = Query(None, description="Filter by severity (same as GET findings)"),
    validated_only: bool = Query(False, description="Only confidence=confirmed"),
    tenant_id: str = Depends(get_current_tenant_id),
) -> StreamingResponse:
    return await _stream_scan_findings_export(
        scan_id, export_format, tenant_id, severity, validated_only
    )


@router.get(
    "/{scan_id}/findings/export.sarif",
    response_class=StreamingResponse,
    response_model=None,
    summary="Export findings as SARIF (shorthand path)",
)
async def export_scan_findings_sarif(
    scan_id: str,
    severity: str | None = Query(None),
    validated_only: bool = Query(False),
    tenant_id: str = Depends(get_current_tenant_id),
) -> StreamingResponse:
    return await _stream_scan_findings_export(
        scan_id, "sarif", tenant_id, severity, validated_only
    )


@router.get(
    "/{scan_id}/findings/export.junit.xml",
    response_class=StreamingResponse,
    response_model=None,
    summary="Export findings as JUnit XML (shorthand path)",
)
async def export_scan_findings_junit(
    scan_id: str,
    severity: str | None = Query(None),
    validated_only: bool = Query(False),
    tenant_id: str = Depends(get_current_tenant_id),
) -> StreamingResponse:
    return await _stream_scan_findings_export(
        scan_id, "junit", tenant_id, severity, validated_only
    )


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

        # Report selection with tier fallback. The Valhalla tier legitimately
        # rejects unproven injection findings (e.g. an XSS finding in a quick scan
        # that skips active injection assessment => generation_status='failed'),
        # while asgard/midgard succeed. So when the requested tier has no usable
        # report we fall back to another tier instead of returning 404/502/503.
        #
        # Preference order favours a report that ALREADY has a stored artifact for
        # the requested format: download_report then streams cached bytes from
        # MinIO instead of running a heavy synchronous on-demand render (WeasyPrint
        # PDF) inside the request path, which can OOM/reset the connection (502).
        base_where = (
            cast(ReportModel.scan_id, String) == scan_id,
            cast(ReportModel.tenant_id, String) == tenant_id,
        )

        async def _newest_report(*extra_where: Any) -> ReportModel | None:
            stmt = (
                select(ReportModel)
                .where(*base_where, *extra_where)
                .order_by(desc(ReportModel.created_at))
                .limit(1)
            )
            return (await session.execute(stmt)).scalar_one_or_none()

        async def _newest_report_with_artifact(prefer_requested_tier: bool) -> ReportModel | None:
            conds = [*base_where, ReportObject.format == fmt]
            if prefer_requested_tier:
                conds.append(ReportModel.tier == tier_norm)
            stmt = (
                select(ReportModel)
                .join(
                    ReportObject,
                    cast(ReportObject.report_id, String) == cast(ReportModel.id, String),
                )
                .where(*conds)
                .order_by(desc(ReportObject.created_at))
                .limit(1)
            )
            return (await session.execute(stmt)).scalar_one_or_none()

        served_tier = tier_norm
        # 1) cached artifact for the requested tier + format (fast, no regen)
        report = await _newest_report_with_artifact(prefer_requested_tier=True)
        # 2) cached artifact of the same format in ANY tier
        if report is None:
            report = await _newest_report_with_artifact(prefer_requested_tier=False)
            if report is not None:
                served_tier = report.tier
        # 3) READY report in the requested tier (on-demand regen for this format)
        if report is None:
            report = await _newest_report(
                ReportModel.tier == tier_norm,
                ReportModel.generation_status == "ready",
            )
        # 4) READY report in ANY tier (Valhalla fails validation in quick scans)
        if report is None:
            report = await _newest_report(ReportModel.generation_status == "ready")
            if report is not None:
                served_tier = report.tier
        # 5) legacy: newest row for the requested tier (last-resort on-demand regen)
        if report is None:
            report = await _newest_report(ReportModel.tier == tier_norm)

    if report is not None and served_tier != tier_norm:
        logger.info(
            json.dumps(
                {
                    "event": "scan_report_tier_fallback",
                    "scan_id": scan_id,
                    "requested_tier": tier_norm,
                    "served_tier": served_tier,
                },
                ensure_ascii=False,
            )
        )

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


@router.get("/{scan_id}/burp-config")
async def export_burp_config(
    scan_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> dict[str, Any]:
    """Export Burp Suite Community Edition configuration JSON for this scan.

    Generates scope items, payload lists, and repeater tabs from findings.
    """
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

        findings_result = await session.execute(
            select(FindingModel).where(
                cast(FindingModel.scan_id, String) == scan_id,
                cast(FindingModel.tenant_id, String) == tenant_id,
            )
        )
        findings_rows = findings_result.scalars().all()

    findings = [
        {
            "title": f.title,
            "severity": f.severity,
            "url": f.description[:200] if f.description else "",
            "cwe": f.cwe,
            "owasp_category": f.owasp_category,
            "payload_attempted": f.payload_attempted or [],
            "payload_successful": f.payload_successful or [],
            "poc": f.proof_of_concept,
        }
        for f in findings_rows
    ]

    try:
        from src.integrations.burp_export import (
            burp_config_to_json,
            generate_burp_config,
        )

        target_url = str(scan.target_url) if hasattr(scan, "target_url") else ""
        scope_config = None
        if scan.options and isinstance(scan.options, dict):
            scope_data = scan.options.get("scope")
            if isinstance(scope_data, dict):
                scope_config = scope_data

        config = generate_burp_config(
            findings=findings,
            scope_config=scope_config,
            target_url=target_url,
        )
        return burp_config_to_json(config)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Burp config generation failed: {exc}",
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


@router.get("/{scan_id}/timeline", response_model=ScanTimelineResponse)
async def get_scan_timeline(
    scan_id: str,
    tenant_id: str = Depends(get_current_tenant_id),
) -> ScanTimelineResponse:
    """Ordered ScanEvent rows with per-step gap and overall wall duration."""
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

        er = await session.execute(
            select(ScanEvent)
            .where(cast(ScanEvent.scan_id, String) == scan_id)
            .order_by(asc(ScanEvent.created_at), asc(ScanEvent.id))
        )
        raw_events = list(er.scalars().all())

    items: list[ScanTimelineEventItem] = []
    prev_ts = None
    for ev in raw_events:
        gap = None
        if prev_ts is not None and ev.created_at is not None:
            gap = (ev.created_at - prev_ts).total_seconds()
        if ev.created_at is not None:
            prev_ts = ev.created_at
        items.append(
            ScanTimelineEventItem(
                id=str(ev.id),
                event=ev.event,
                phase=ev.phase,
                progress=ev.progress,
                message=ev.message,
                created_at=format_created_at_iso_z(ev.created_at),
                duration_sec=float(ev.duration_sec) if ev.duration_sec is not None else None,
                gap_from_previous_sec=gap,
            )
        )

    total_duration = 0.0
    if len(raw_events) >= 2:
        first_at = raw_events[0].created_at
        last_at = raw_events[-1].created_at
        if first_at is not None and last_at is not None:
            total_duration = max(0.0, (last_at - first_at).total_seconds())

    return ScanTimelineResponse(
        scan_id=scan_id,
        events=items,
        total_duration_sec=total_duration,
    )


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
    Emits: phase_start, progress, complete, error, keepalive (every 15s).
    Polls scan_events until complete/failed. Keepalive comments prevent nginx/proxy timeouts."""
    async def event_generator():
        try:
            seen_event_ids: set[str] = set()
            started_at = time.monotonic()
            last_keepalive = started_at

            while True:
                now = time.monotonic()

                # Emit SSE keepalive comment every SSE_KEEPALIVE_INTERVAL_SEC
                if now - last_keepalive >= SSE_KEEPALIVE_INTERVAL_SEC:
                    yield {"event": "keepalive", "data": "", "comment": f"ping - {now}"}
                    last_keepalive = now

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
            "X-Content-Type-Options": "nosniff",
        },
        # ping_interval is sse_starlette >=2.0 only; skip for backward compat
    )
