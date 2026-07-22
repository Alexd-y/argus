"""Web Workbench Repeater endpoints — tabs + scope-gated replay (WB-P3b-2).

Versioned under ``/api/v1/wb`` (contract in ``docs/api-contracts.md``). Every
request is tenant-scoped (RLS via ``set_session_tenant`` + explicit filters).

Security invariants:

* **Replay only through the gate (SI-WB-1)** — every replay is evaluated by
  :class:`RepeaterService` (scope, then the optional preflight hook) BEFORE any
  byte leaves the process; a blocked replay never touches the sender.
* **Kill-switch** — replay is refused unless the project is ``active``.
* **Every replay recorded** — forwarded or blocked, the outcome is persisted as
  an exchange (audit). Transport failures are surfaced (502) without a partial
  record.
* Raw bytes travel as base64, are byte-exact, and are never logged.
"""

from __future__ import annotations

import base64
import binascii
import logging
from typing import Annotated

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routers.web_workbench.projects import tenant_session
from src.web_workbench.contracts import ProjectStatus
from src.web_workbench.contracts.repeater import (
    RepeaterExchangeDTO,
    RepeaterExchangeListResponse,
    RepeaterReplayRequest,
    RepeaterTabCreate,
    RepeaterTabDTO,
    RepeaterTabUpdate,
)
from src.web_workbench.projects.repository import WorkbenchProjectRepository
from src.web_workbench.projects.service import ProjectScopeService
from src.web_workbench.proxy.transport import HttpMessageError
from src.web_workbench.repeater.engine import RepeaterService
from src.web_workbench.repeater.repository import (
    OptimisticLockError,
    ProjectNotFoundError,
    RepeaterRepository,
    TabNotFoundError,
)
from src.web_workbench.repeater.sender import HttpxSender

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/wb", tags=["web-workbench-repeater"])

_repository = RepeaterRepository()
_projects = WorkbenchProjectRepository()

_Ctx = Annotated[tuple[AsyncSession, str], Depends(tenant_session)]


def _decode_b64(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"{field} is not valid base64") from exc


# -- tabs --------------------------------------------------------------------


@router.post(
    "/projects/{project_id}/repeater/tabs",
    response_model=RepeaterTabDTO,
    status_code=201,
)
async def create_tab(project_id: str, body: RepeaterTabCreate, ctx: _Ctx) -> RepeaterTabDTO:
    session, tenant_id = ctx
    raw = _decode_b64(body.raw_request_base64, "raw_request_base64")
    try:
        return await _repository.create_tab(session, tenant_id, project_id, body, raw_request=raw)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc


@router.get("/projects/{project_id}/repeater/tabs", response_model=list[RepeaterTabDTO])
async def list_tabs(project_id: str, ctx: _Ctx) -> list[RepeaterTabDTO]:
    session, tenant_id = ctx
    return await _repository.list_tabs(session, tenant_id, project_id)


@router.get("/repeater/tabs/{tab_id}", response_model=RepeaterTabDTO)
async def get_tab(tab_id: str, ctx: _Ctx) -> RepeaterTabDTO:
    session, tenant_id = ctx
    tab = await _repository.get_tab(session, tenant_id, tab_id)
    if tab is None:
        raise HTTPException(status_code=404, detail="tab not found")
    return tab


@router.patch("/repeater/tabs/{tab_id}", response_model=RepeaterTabDTO)
async def update_tab(tab_id: str, body: RepeaterTabUpdate, ctx: _Ctx) -> RepeaterTabDTO:
    session, tenant_id = ctx
    raw = (
        _decode_b64(body.raw_request_base64, "raw_request_base64")
        if body.raw_request_base64
        else None
    )
    try:
        return await _repository.update_tab(session, tenant_id, tab_id, body, raw_request=raw)
    except TabNotFoundError as exc:
        raise HTTPException(status_code=404, detail="tab not found") from exc
    except OptimisticLockError as exc:
        raise HTTPException(status_code=409, detail="version conflict; reload and retry") from exc


@router.delete("/repeater/tabs/{tab_id}", status_code=204)
async def delete_tab(tab_id: str, ctx: _Ctx) -> None:
    session, tenant_id = ctx
    try:
        await _repository.delete_tab(session, tenant_id, tab_id)
    except TabNotFoundError as exc:
        raise HTTPException(status_code=404, detail="tab not found") from exc


# -- replay + history --------------------------------------------------------


@router.post("/repeater/tabs/{tab_id}/replay", response_model=RepeaterExchangeDTO)
async def replay_tab(tab_id: str, body: RepeaterReplayRequest, ctx: _Ctx) -> RepeaterExchangeDTO:
    session, tenant_id = ctx
    tab = await _repository.get_tab(session, tenant_id, tab_id)
    if tab is None:
        raise HTTPException(status_code=404, detail="tab not found")

    project = await _projects.get(session, tenant_id, tab.project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    if project.status is not ProjectStatus.ACTIVE:
        # Kill-switch: no active operations against a paused/archived project.
        raise HTTPException(status_code=409, detail="project is not active")

    if body.raw_request_base64 is not None:
        raw = _decode_b64(body.raw_request_base64, "raw_request_base64")
    else:
        raw = base64.b64decode(tab.raw_request_base64)

    # Mandatory gate (scope first). The live surface additionally wires a
    # PreflightChecker-backed hook (ownership/policy/approval) — see WB-P2b.
    scope_service = ProjectScopeService(project.scope_rules)
    service = RepeaterService(scope_service)
    sender = HttpxSender()

    try:
        result = service.replay(raw, sender)
    except HttpMessageError as exc:
        raise HTTPException(status_code=400, detail="malformed request") from exc
    except httpx.HTTPError as exc:
        # Allowed + in-scope, but the upstream send failed at the transport
        # layer; surface without leaking internals or a partial record.
        logger.info("repeater upstream send failed", extra={"tab_id": tab_id})
        raise HTTPException(status_code=502, detail="upstream request failed") from exc

    return await _repository.record_exchange(
        session,
        tenant_id,
        project_id=tab.project_id,
        tab_id=tab_id,
        raw_request=raw,
        result=result,
    )


@router.get("/repeater/tabs/{tab_id}/exchanges", response_model=RepeaterExchangeListResponse)
async def list_exchanges(
    tab_id: str,
    ctx: _Ctx,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> RepeaterExchangeListResponse:
    session, tenant_id = ctx
    items, total = await _repository.list_exchanges(
        session, tenant_id, tab_id, offset=offset, limit=limit
    )
    return RepeaterExchangeListResponse(items=tuple(items), total=total, offset=offset, limit=limit)


@router.get("/repeater/exchanges/{exchange_id}", response_model=RepeaterExchangeDTO)
async def get_exchange(exchange_id: str, ctx: _Ctx) -> RepeaterExchangeDTO:
    session, tenant_id = ctx
    exchange = await _repository.get_exchange(session, tenant_id, exchange_id)
    if exchange is None:
        raise HTTPException(status_code=404, detail="exchange not found")
    return exchange


__all__ = ["router"]
