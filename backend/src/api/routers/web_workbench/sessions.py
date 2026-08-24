"""Web Workbench Sessions endpoints — macros + principals (WB-P6b).

Versioned under ``/api/v1/wb`` (contract in ``docs/api-contracts.md``). Every
request is tenant-scoped (RLS via ``set_session_tenant`` + explicit filters).

Security invariants:

* **Split-plane secrets (SI-3)** — no raw credential/token is accepted or
  returned. A macro references secrets by ``secret_ref`` placeholder inside its
  ``steps``; a principal carries only ``secrets_ref`` (a handle). Values are
  resolved in-process at replay time and never persisted or echoed here.
* Optimistic locking guards concurrent edits (409 on version mismatch).
* Live owner/attacker replay itself runs through the gate on the worker plane
  (WB-P6b live path) — this router persists the definitions only.
"""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.routers.web_workbench.projects import tenant_session
from src.web_workbench.contracts.sessions import (
    SessionMacroCreate,
    SessionMacroDTO,
    SessionMacroUpdate,
    SessionPrincipalCreate,
    SessionPrincipalDTO,
    SessionPrincipalUpdate,
)
from src.web_workbench.sessions.repository import (
    InvalidRoleError,
    MacroNotFoundError,
    NameConflictError,
    OptimisticLockError,
    PrincipalNotFoundError,
    ProjectNotFoundError,
    SessionRepository,
)
from src.web_workbench.sessions.repository import (
    SessionMacroDTO as SessionMacroRow,
)
from src.web_workbench.sessions.repository import (
    SessionPrincipalDTO as SessionPrincipalRow,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/wb", tags=["web-workbench-sessions"])

_repository = SessionRepository()

_Ctx = Annotated[tuple[AsyncSession, str], Depends(tenant_session)]


def _macro_to_api(row: SessionMacroRow) -> SessionMacroDTO:
    return SessionMacroDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        name=row.name,
        steps=row.steps,
        match_rules=row.match_rules,
        config=row.config,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


def _principal_to_api(row: SessionPrincipalRow) -> SessionPrincipalDTO:
    return SessionPrincipalDTO(
        id=row.id,
        tenant_id=row.tenant_id,
        project_id=row.project_id,
        name=row.name,
        role=row.role,
        secrets_ref=row.secrets_ref,
        macro_id=row.macro_id,
        config=row.config,
        version=row.version,
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


# -- macros ------------------------------------------------------------------


@router.post(
    "/projects/{project_id}/sessions/macros",
    response_model=SessionMacroDTO,
    status_code=201,
)
async def create_macro(project_id: str, body: SessionMacroCreate, ctx: _Ctx) -> SessionMacroDTO:
    session, tenant_id = ctx
    try:
        row = await _repository.create_macro(
            session,
            tenant_id,
            project_id,
            name=body.name,
            steps=body.steps,
            match_rules=body.match_rules,
            config=body.config,
        )
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except NameConflictError as exc:
        raise HTTPException(status_code=409, detail="macro name already exists") from exc
    return _macro_to_api(row)


@router.get(
    "/projects/{project_id}/sessions/macros",
    response_model=list[SessionMacroDTO],
)
async def list_macros(project_id: str, ctx: _Ctx) -> list[SessionMacroDTO]:
    session, tenant_id = ctx
    rows = await _repository.list_macros(session, tenant_id, project_id)
    return [_macro_to_api(r) for r in rows]


@router.get("/sessions/macros/{macro_id}", response_model=SessionMacroDTO)
async def get_macro(macro_id: str, ctx: _Ctx) -> SessionMacroDTO:
    session, tenant_id = ctx
    row = await _repository.get_macro(session, tenant_id, macro_id)
    if row is None:
        raise HTTPException(status_code=404, detail="macro not found")
    return _macro_to_api(row)


@router.patch("/sessions/macros/{macro_id}", response_model=SessionMacroDTO)
async def update_macro(macro_id: str, body: SessionMacroUpdate, ctx: _Ctx) -> SessionMacroDTO:
    session, tenant_id = ctx
    try:
        row = await _repository.update_macro(
            session,
            tenant_id,
            macro_id,
            expected_version=body.expected_version,
            name=body.name,
            steps=body.steps,
            match_rules=body.match_rules,
            config=body.config,
        )
    except MacroNotFoundError as exc:
        raise HTTPException(status_code=404, detail="macro not found") from exc
    except OptimisticLockError as exc:
        raise HTTPException(status_code=409, detail="version conflict; reload and retry") from exc
    except NameConflictError as exc:
        raise HTTPException(status_code=409, detail="macro name already exists") from exc
    return _macro_to_api(row)


@router.delete("/sessions/macros/{macro_id}", status_code=204)
async def delete_macro(macro_id: str, ctx: _Ctx) -> None:
    session, tenant_id = ctx
    try:
        await _repository.delete_macro(session, tenant_id, macro_id)
    except MacroNotFoundError as exc:
        raise HTTPException(status_code=404, detail="macro not found") from exc


# -- principals --------------------------------------------------------------


@router.post(
    "/projects/{project_id}/sessions/principals",
    response_model=SessionPrincipalDTO,
    status_code=201,
)
async def create_principal(
    project_id: str, body: SessionPrincipalCreate, ctx: _Ctx
) -> SessionPrincipalDTO:
    session, tenant_id = ctx
    try:
        row = await _repository.create_principal(
            session,
            tenant_id,
            project_id,
            name=body.name,
            role=body.role,
            secrets_ref=body.secrets_ref,
            macro_id=body.macro_id,
            config=body.config,
        )
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    except MacroNotFoundError as exc:
        raise HTTPException(status_code=404, detail="macro not found") from exc
    except InvalidRoleError as exc:
        raise HTTPException(status_code=422, detail="invalid principal role") from exc
    except NameConflictError as exc:
        raise HTTPException(status_code=409, detail="principal name already exists") from exc
    return _principal_to_api(row)


@router.get(
    "/projects/{project_id}/sessions/principals",
    response_model=list[SessionPrincipalDTO],
)
async def list_principals(project_id: str, ctx: _Ctx) -> list[SessionPrincipalDTO]:
    session, tenant_id = ctx
    rows = await _repository.list_principals(session, tenant_id, project_id)
    return [_principal_to_api(r) for r in rows]


@router.get("/sessions/principals/{principal_id}", response_model=SessionPrincipalDTO)
async def get_principal(principal_id: str, ctx: _Ctx) -> SessionPrincipalDTO:
    session, tenant_id = ctx
    row = await _repository.get_principal(session, tenant_id, principal_id)
    if row is None:
        raise HTTPException(status_code=404, detail="principal not found")
    return _principal_to_api(row)


@router.patch("/sessions/principals/{principal_id}", response_model=SessionPrincipalDTO)
async def update_principal(
    principal_id: str, body: SessionPrincipalUpdate, ctx: _Ctx
) -> SessionPrincipalDTO:
    session, tenant_id = ctx
    try:
        row = await _repository.update_principal(
            session,
            tenant_id,
            principal_id,
            expected_version=body.expected_version,
            name=body.name,
            role=body.role,
            secrets_ref=body.secrets_ref,
            macro_id=body.macro_id,
            config=body.config,
        )
    except PrincipalNotFoundError as exc:
        raise HTTPException(status_code=404, detail="principal not found") from exc
    except MacroNotFoundError as exc:
        raise HTTPException(status_code=404, detail="macro not found") from exc
    except InvalidRoleError as exc:
        raise HTTPException(status_code=422, detail="invalid principal role") from exc
    except OptimisticLockError as exc:
        raise HTTPException(status_code=409, detail="version conflict; reload and retry") from exc
    except NameConflictError as exc:
        raise HTTPException(status_code=409, detail="principal name already exists") from exc
    return _principal_to_api(row)


@router.delete("/sessions/principals/{principal_id}", status_code=204)
async def delete_principal(principal_id: str, ctx: _Ctx) -> None:
    session, tenant_id = ctx
    try:
        await _repository.delete_principal(session, tenant_id, principal_id)
    except PrincipalNotFoundError as exc:
        raise HTTPException(status_code=404, detail="principal not found") from exc


__all__ = ["router"]
