"""Web Workbench project / scope / EAP endpoints (WB-P1b).

Versioned under ``/api/v1/wb/projects`` (contract documented in
``docs/api-contracts.md``). Every request is tenant-scoped: the session has
``set_session_tenant`` applied so PostgreSQL RLS filters rows, and the
repository additionally filters ``tenant_id`` explicitly (defence-in-depth).

Error handling never leaks internals to the client (user rule / SI): repository
exceptions map to clean HTTP status codes with closed-taxonomy detail strings.
EAP attach is fail-closed — an unsigned / invalid / expired profile is rejected
with 422 and the closed reason.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.tenant import get_current_tenant_id
from src.db.session import async_session_factory, set_session_tenant
from src.policy.audit import AuditLogger, InMemoryAuditSink
from src.policy.engagement_authorization import EngagementAuthorizationService
from src.sandbox.signing import KeyManager
from src.web_workbench.contracts import (
    EapAttachRequest,
    ProjectStatus,
    WorkbenchEapView,
    WorkbenchProjectCreate,
    WorkbenchProjectDTO,
    WorkbenchProjectListResponse,
    WorkbenchProjectUpdate,
)
from src.web_workbench.projects.repository import (
    EapRejectedError,
    OptimisticLockError,
    ProjectNameConflictError,
    ProjectNotFoundError,
    WorkbenchProjectRepository,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/wb/projects", tags=["web-workbench"])

_repository = WorkbenchProjectRepository()


async def tenant_session(
    tenant_id: Annotated[str, Depends(get_current_tenant_id)],
) -> AsyncGenerator[tuple[AsyncSession, str], None]:
    """Yield ``(session, tenant_id)`` with RLS tenant context applied."""
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        try:
            yield session, tenant_id
            await session.commit()
        except Exception:
            await session.rollback()
            raise


def get_eap_service() -> EngagementAuthorizationService:
    """Build the EAP verification service from the configured keys directory.

    Fail-closed: a missing / empty keys directory loads zero keys, so every
    submitted EAP fails verification and is rejected.
    """
    key_manager = KeyManager(Path(settings.wb_eap_keys_dir))
    key_manager.load()
    return EngagementAuthorizationService(
        key_manager=key_manager,
        audit_logger=AuditLogger(InMemoryAuditSink()),
    )


@router.post("", response_model=WorkbenchProjectDTO, status_code=201)
async def create_project(
    body: WorkbenchProjectCreate,
    ctx: Annotated[tuple[AsyncSession, str], Depends(tenant_session)],
) -> WorkbenchProjectDTO:
    session, tenant_id = ctx
    try:
        return await _repository.create(session, tenant_id, body)
    except ProjectNameConflictError as exc:
        raise HTTPException(status_code=409, detail="project name already exists") from exc


@router.get("", response_model=WorkbenchProjectListResponse)
async def list_projects(
    ctx: Annotated[tuple[AsyncSession, str], Depends(tenant_session)],
    status: ProjectStatus | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=200),
) -> WorkbenchProjectListResponse:
    session, tenant_id = ctx
    items, total = await _repository.list(
        session, tenant_id, status=status, offset=offset, limit=limit
    )
    return WorkbenchProjectListResponse(items=tuple(items), total=total, offset=offset, limit=limit)


@router.get("/{project_id}", response_model=WorkbenchProjectDTO)
async def get_project(
    project_id: str,
    ctx: Annotated[tuple[AsyncSession, str], Depends(tenant_session)],
) -> WorkbenchProjectDTO:
    session, tenant_id = ctx
    project = await _repository.get(session, tenant_id, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project not found")
    return project


@router.patch("/{project_id}", response_model=WorkbenchProjectDTO)
async def update_project(
    project_id: str,
    body: WorkbenchProjectUpdate,
    ctx: Annotated[tuple[AsyncSession, str], Depends(tenant_session)],
) -> WorkbenchProjectDTO:
    session, tenant_id = ctx
    try:
        return await _repository.update(session, tenant_id, project_id, body)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except OptimisticLockError as exc:
        raise HTTPException(status_code=409, detail="version conflict; reload and retry") from exc
    except ProjectNameConflictError as exc:
        raise HTTPException(status_code=409, detail="project name already exists") from exc


@router.post("/{project_id}/eap", response_model=WorkbenchEapView, status_code=201)
async def attach_eap(
    project_id: str,
    body: EapAttachRequest,
    ctx: Annotated[tuple[AsyncSession, str], Depends(tenant_session)],
    eap_service: Annotated[EngagementAuthorizationService, Depends(get_eap_service)],
) -> WorkbenchEapView:
    session, tenant_id = ctx
    try:
        return await _repository.attach_eap(
            session,
            tenant_id,
            project_id,
            body.signed_profile,
            eap_service=eap_service,
        )
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except EapRejectedError as exc:
        raise HTTPException(status_code=422, detail=f"eap rejected: {exc.reason}") from exc


__all__ = ["router"]
