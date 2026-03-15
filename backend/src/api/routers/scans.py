"""Scans router — POST /scans, GET /scans/:id, GET /scans/:id/events."""

import asyncio
import json
import time
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import cast, select, String
from sse_starlette.sse import EventSourceResponse

SSE_POLL_INTERVAL_SEC = 1.5
SSE_MAX_WAIT_SEC = 300

from src.api.schemas import (
    Finding,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanDetailResponse,
)
from src.core.config import settings
from src.core.observability import record_scan_started
from src.core.tenant import get_current_tenant_id
from src.db.models import Finding as FindingModel
from src.db.models import Scan, ScanEvent, Target, Tenant
from src.db.session import async_session_factory, set_session_tenant
from src.tasks import scan_phase_task

router = APIRouter(prefix="/scans", tags=["scans"])

DEFAULT_TENANT_ID = settings.default_tenant_id


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
            created_at=scan.created_at.isoformat()
            if scan.created_at
            else datetime.now(UTC).isoformat(),
        )


def _finding_to_schema(f: FindingModel) -> Finding:
    """Convert DB finding to API schema."""
    return Finding(
        severity=f.severity,
        title=f.title,
        description=f.description or "",
        cwe=f.cwe,
        cvss=f.cvss,
    )


@router.get("/{scan_id}/findings", response_model=list[Finding])
async def get_scan_findings(
    scan_id: str,
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
        result = await session.execute(
            select(FindingModel).where(cast(FindingModel.scan_id, String) == scan_id)
        )
        findings = list(result.scalars().all())
        return [_finding_to_schema(f) for f in findings]


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
    return _format_sse_event("error", {"event": "error", "error": message})


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
