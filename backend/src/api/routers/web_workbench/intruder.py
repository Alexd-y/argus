"""Web Workbench Intruder endpoints — attacks + gated high-volume execution (WB-P4b).

Versioned under ``/api/v1/wb`` (contract in ``docs/api-contracts.md``). Every
request is tenant-scoped (RLS via ``set_session_tenant`` + explicit filters).

Security invariants:

* **Execution only through the gate (SI-WB-1)** — the API never sends bytes; it
  dispatches the run to the ``argus.intruder.highvol`` Celery pool, where
  :class:`~src.web_workbench.intruder.service.IntruderService` evaluates every
  request through :class:`ForwardGate` (scope) before egress.
* **Kill-switch** — start/resume are refused unless the project is ``active``;
  ``cancel`` writes a terminal status the running worker observes and drops on.
* **Payloads by reference (SI-5)** — ``payload_config`` stores registry
  references only; the worker materialises them through the signed
  ``PayloadBuilder``. Result rows are metadata-only (no raw payload bytes).
* Optimistic locking guards operator-driven status transitions.
"""

from __future__ import annotations

import base64
import binascii
import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routers.web_workbench.projects import tenant_session
from src.web_workbench.contracts import ProjectStatus
from src.web_workbench.contracts.intruder import (
    IntruderAttackCreate,
    IntruderAttackDTO,
    IntruderControlRequest,
    IntruderPosition,
    IntruderRequestDTO,
    IntruderRequestListResponse,
)
from src.web_workbench.intruder.repository import (
    STATUS_CANCELLED,
    STATUS_PAUSED,
    STATUS_QUEUED,
    AttackNameConflictError,
    AttackNotFoundError,
    IntruderRepository,
    OptimisticLockError,
    ProjectNotFoundError,
)
from src.web_workbench.intruder.repository import (
    IntruderAttackDTO as IntruderAttackRow,
)
from src.web_workbench.intruder.repository import (
    IntruderRequestDTO as IntruderRequestRow,
)
from src.web_workbench.intruder.tasks import run_intruder_attack
from src.web_workbench.projects.repository import WorkbenchProjectRepository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/wb", tags=["web-workbench-intruder"])

_repository = IntruderRepository()
_projects = WorkbenchProjectRepository()

_Ctx = Annotated[tuple[AsyncSession, str], Depends(tenant_session)]


def _decode_b64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"{field} is not valid base64") from exc


def _attack_to_api(row: IntruderAttackRow) -> IntruderAttackDTO:
    positions = (
        [IntruderPosition(start=p["start"], end=p["end"]) for p in row.positions]
        if row.positions is not None
        else None
    )
    return IntruderAttackDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        name=row.name,
        attack_type=row.attack_type,
        status=row.status,
        raw_request_template_base64=base64.b64encode(row.raw_request_template).decode("ascii"),
        positions=positions,
        payload_config=row.payload_config,
        config=row.config,
        checkpoint=row.checkpoint,
        requests_total=row.requests_total,
        requests_completed=row.requests_completed,
        findings_total=row.findings_total,
        error_reason=row.error_reason,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _request_to_api(row: IntruderRequestRow) -> IntruderRequestDTO:
    return IntruderRequestDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        attack_id=row.attack_id,
        request_index=row.request_index,
        payload_label=row.payload_label,
        payload_index=row.payload_index,
        forward_outcome=row.forward_outcome,
        block_reason=row.block_reason,
        status_code=row.status_code,
        response_length=row.response_length,
        response_time_ms=row.response_time_ms,
        response_sha256=row.response_sha256,
        flagged=row.flagged,
        error_reason=row.error_reason,
        created_at=row.created_at,
    )


# -- attacks -----------------------------------------------------------------


@router.post(
    "/projects/{project_id}/intruder/attacks",
    response_model=IntruderAttackDTO,
    status_code=201,
)
async def create_attack(
    project_id: str, body: IntruderAttackCreate, ctx: _Ctx
) -> IntruderAttackDTO:
    session, tenant_id = ctx
    raw = _decode_b64(body.raw_request_template_base64, "raw_request_template_base64")
    positions = (
        [{"start": p.start, "end": p.end} for p in body.positions]
        if body.positions is not None
        else None
    )
    try:
        row = await _repository.create_attack(
            session,
            tenant_id,
            project_id,
            name=body.name,
            attack_type=body.attack_type,
            raw_request_template=raw,
            positions=positions,
            payload_config=body.payload_config,
            config=body.config,
        )
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except AttackNameConflictError as exc:
        raise HTTPException(status_code=409, detail="attack name already exists") from exc
    return _attack_to_api(row)


@router.get(
    "/projects/{project_id}/intruder/attacks",
    response_model=list[IntruderAttackDTO],
)
async def list_attacks(project_id: str, ctx: _Ctx) -> list[IntruderAttackDTO]:
    session, tenant_id = ctx
    rows = await _repository.list_attacks(session, tenant_id, project_id)
    return [_attack_to_api(r) for r in rows]


@router.get("/intruder/attacks/{attack_id}", response_model=IntruderAttackDTO)
async def get_attack(attack_id: str, ctx: _Ctx) -> IntruderAttackDTO:
    session, tenant_id = ctx
    row = await _repository.get_attack(session, tenant_id, attack_id)
    if row is None:
        raise HTTPException(status_code=404, detail="attack not found")
    return _attack_to_api(row)


# -- lifecycle control -------------------------------------------------------


async def _load_active_attack(
    session: AsyncSession, tenant_id: str, attack_id: str
) -> IntruderAttackRow:
    """Fetch the attack and enforce the project kill-switch (active only)."""
    row = await _repository.get_attack(session, tenant_id, attack_id)
    if row is None:
        raise HTTPException(status_code=404, detail="attack not found")
    project = await _projects.get(session, tenant_id, row.project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    if project.status is not ProjectStatus.ACTIVE:
        raise HTTPException(status_code=409, detail="project is not active")
    return row


@router.post("/intruder/attacks/{attack_id}/start", response_model=IntruderAttackDTO)
async def start_attack(
    attack_id: str, body: IntruderControlRequest, ctx: _Ctx
) -> IntruderAttackDTO:
    session, tenant_id = ctx
    await _load_active_attack(session, tenant_id, attack_id)
    try:
        row = await _repository.set_status(
            session, tenant_id, attack_id, STATUS_QUEUED, expected_version=body.expected_version
        )
    except AttackNotFoundError as exc:
        raise HTTPException(status_code=404, detail="attack not found") from exc
    except OptimisticLockError as exc:
        raise HTTPException(status_code=409, detail="version conflict; reload and retry") from exc
    # Commit the status transition before dispatch so the worker observes it.
    await session.commit()
    run_intruder_attack.delay(tenant_id, attack_id)
    return _attack_to_api(row)


@router.post("/intruder/attacks/{attack_id}/resume", response_model=IntruderAttackDTO)
async def resume_attack(
    attack_id: str, body: IntruderControlRequest, ctx: _Ctx
) -> IntruderAttackDTO:
    # Resume shares start semantics: re-queue + re-dispatch. The runner skips
    # already-recorded indices via the persisted checkpoint (idempotent).
    return await start_attack(attack_id, body, ctx)


@router.post("/intruder/attacks/{attack_id}/pause", response_model=IntruderAttackDTO)
async def pause_attack(
    attack_id: str, body: IntruderControlRequest, ctx: _Ctx
) -> IntruderAttackDTO:
    session, tenant_id = ctx
    try:
        row = await _repository.set_status(
            session, tenant_id, attack_id, STATUS_PAUSED, expected_version=body.expected_version
        )
    except AttackNotFoundError as exc:
        raise HTTPException(status_code=404, detail="attack not found") from exc
    except OptimisticLockError as exc:
        raise HTTPException(status_code=409, detail="version conflict; reload and retry") from exc
    return _attack_to_api(row)


@router.post("/intruder/attacks/{attack_id}/cancel", response_model=IntruderAttackDTO)
async def cancel_attack(
    attack_id: str, body: IntruderControlRequest, ctx: _Ctx
) -> IntruderAttackDTO:
    session, tenant_id = ctx
    try:
        row = await _repository.set_status(
            session, tenant_id, attack_id, STATUS_CANCELLED, expected_version=body.expected_version
        )
    except AttackNotFoundError as exc:
        raise HTTPException(status_code=404, detail="attack not found") from exc
    except OptimisticLockError as exc:
        raise HTTPException(status_code=409, detail="version conflict; reload and retry") from exc
    return _attack_to_api(row)


# -- results -----------------------------------------------------------------


@router.get(
    "/intruder/attacks/{attack_id}/requests",
    response_model=IntruderRequestListResponse,
)
async def list_requests(
    attack_id: str,
    ctx: _Ctx,
    flagged: bool = Query(False),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=500),
) -> IntruderRequestListResponse:
    session, tenant_id = ctx
    items, total = await _repository.list_requests(
        session, tenant_id, attack_id, flagged_only=flagged, offset=offset, limit=limit
    )
    return IntruderRequestListResponse(
        items=tuple(_request_to_api(r) for r in items),
        total=total,
        offset=offset,
        limit=limit,
    )


__all__ = ["router"]
