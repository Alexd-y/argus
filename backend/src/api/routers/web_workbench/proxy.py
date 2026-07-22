"""Web Workbench proxy endpoints — listeners + traffic history (WB-P2a-2).

Versioned under ``/api/v1/wb`` (contract in ``docs/api-contracts.md``). Every
request is tenant-scoped (RLS via ``set_session_tenant`` + explicit filters).
Listener writes use optimistic locking. Errors never leak internals.

CA issuance/rotation (WB-P2b-1) seals the CA private key with an external KEK
and returns only the public certificate. Live traffic capture via the mitm
daemon is WB-P2b-2.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routers.web_workbench.projects import tenant_session
from src.web_workbench.contracts.proxy import (
    CaIssueRequest,
    ProxyListenerCreate,
    ProxyListenerDTO,
    ProxyListenerUpdate,
    TrafficListResponse,
    TrafficMessageDTO,
)
from src.web_workbench.proxy.ca_lifecycle import build_sealer_from_settings, issue_ca
from src.web_workbench.proxy.repository import (
    ListenerNameConflictError,
    ListenerNotFoundError,
    OptimisticLockError,
    ProjectNotFoundError,
    ProxyRepository,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/wb", tags=["web-workbench-proxy"])

_repository = ProxyRepository()

_Ctx = Annotated[tuple[AsyncSession, str], Depends(tenant_session)]


@router.post(
    "/projects/{project_id}/proxy/listeners",
    response_model=ProxyListenerDTO,
    status_code=201,
)
async def create_listener(
    project_id: str, body: ProxyListenerCreate, ctx: _Ctx
) -> ProxyListenerDTO:
    session, tenant_id = ctx
    try:
        return await _repository.create_listener(session, tenant_id, project_id, body)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except ListenerNameConflictError as exc:
        raise HTTPException(status_code=409, detail="listener name already exists") from exc


@router.get(
    "/projects/{project_id}/proxy/listeners",
    response_model=list[ProxyListenerDTO],
)
async def list_listeners(project_id: str, ctx: _Ctx) -> list[ProxyListenerDTO]:
    session, tenant_id = ctx
    return await _repository.list_listeners(session, tenant_id, project_id)


@router.get("/proxy/listeners/{listener_id}", response_model=ProxyListenerDTO)
async def get_listener(listener_id: str, ctx: _Ctx) -> ProxyListenerDTO:
    session, tenant_id = ctx
    listener = await _repository.get_listener(session, tenant_id, listener_id)
    if listener is None:
        raise HTTPException(status_code=404, detail="listener not found")
    return listener


@router.patch("/proxy/listeners/{listener_id}", response_model=ProxyListenerDTO)
async def update_listener(
    listener_id: str, body: ProxyListenerUpdate, ctx: _Ctx
) -> ProxyListenerDTO:
    session, tenant_id = ctx
    try:
        return await _repository.update_listener(session, tenant_id, listener_id, body)
    except ListenerNotFoundError as exc:
        raise HTTPException(status_code=404, detail="listener not found") from exc
    except OptimisticLockError as exc:
        raise HTTPException(status_code=409, detail="version conflict; reload and retry") from exc
    except ListenerNameConflictError as exc:
        raise HTTPException(status_code=409, detail="listener name already exists") from exc


@router.post("/proxy/listeners/{listener_id}/ca", response_model=ProxyListenerDTO)
async def issue_listener_ca(listener_id: str, body: CaIssueRequest, ctx: _Ctx) -> ProxyListenerDTO:
    """Issue or rotate the listener's MITM CA (public cert returned only).

    Fail-closed: without a configured sealing key (``WB_CA_SEALING_KEY``) the
    CA private key cannot be sealed, so issuance is refused with 503 rather than
    persisting an unsealed key.
    """
    session, tenant_id = ctx
    sealer = build_sealer_from_settings()
    if sealer is None:
        raise HTTPException(status_code=503, detail="ca issuance unavailable: no sealing key")
    sealed = issue_ca(sealer, common_name=body.common_name)
    try:
        return await _repository.set_listener_ca(
            session,
            tenant_id,
            listener_id,
            sealed,
            expected_version=body.expected_version,
        )
    except ListenerNotFoundError as exc:
        raise HTTPException(status_code=404, detail="listener not found") from exc
    except OptimisticLockError as exc:
        raise HTTPException(status_code=409, detail="version conflict; reload and retry") from exc


@router.get("/projects/{project_id}/proxy/history", response_model=TrafficListResponse)
async def list_history(
    project_id: str,
    ctx: _Ctx,
    host: str | None = Query(None, max_length=255),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
) -> TrafficListResponse:
    session, tenant_id = ctx
    items, total = await _repository.list_history(
        session, tenant_id, project_id, host=host, offset=offset, limit=limit
    )
    return TrafficListResponse(items=tuple(items), total=total, offset=offset, limit=limit)


@router.get("/proxy/messages/{message_id}", response_model=TrafficMessageDTO)
async def get_message(message_id: str, ctx: _Ctx) -> TrafficMessageDTO:
    session, tenant_id = ctx
    message = await _repository.get_message(session, tenant_id, message_id)
    if message is None:
        raise HTTPException(status_code=404, detail="message not found")
    return message


__all__ = ["router"]
