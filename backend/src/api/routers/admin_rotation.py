"""LLM rotation Admin API (WP C) — view / set the multi-LLM rotation chain.

GET  /api/v1/admin/rotation         — current rotation state (?tenant_id=&role=&scan_id=)
POST /api/v1/admin/rotation         — set the ordered profile chain / reset cursor

Rotation is applied only to safe (non-sensitive) roles; WRB-001 keeps sensitive
pentest analysis WRB-first regardless of this chain. MFA-gated; the tenant travels
explicitly (no session principal under the legacy ``X-Admin-Key`` shim) and is set
as the RLS tenant before any read/write.
"""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from src.api.routers.admin_findings import (
    _admin_role_dep,
    _admin_tenant_dep,
    _enforce_rbac,
)
from src.auth.admin_dependencies import require_admin_mfa_passed
from src.db.session import async_session_factory, set_session_tenant
from src.governance import stores
from src.llm.rotation import LLMRotation

router = APIRouter(prefix="/admin/rotation", tags=["admin_rotation"])


class RotationSet(BaseModel):
    tenant_id: str
    role: str = "report"
    profile_ids: list[str] = Field(default_factory=list)
    scan_id: str | None = None


class RotationState(BaseModel):
    role: str
    scan_id: str | None
    profile_ids: list[str]
    cursor: int
    excluded: list[str]


def _require_tenant(tenant_id: str) -> str:
    try:
        uuid.UUID(str(tenant_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="invalid tenant_id") from exc
    return tenant_id


@router.get("", response_model=RotationState)
async def get_rotation(
    _: Annotated[None, Depends(require_admin_mfa_passed)],
    admin_role: Annotated[str, Depends(_admin_role_dep)],
    role_tenant: Annotated[str | None, Depends(_admin_tenant_dep)],
    tenant_id: str = Query(...),
    role: str = "report",
    scan_id: str | None = None,
) -> RotationState:
    tenant_id = _require_tenant(tenant_id)
    _enforce_rbac(role=admin_role, role_tenant=role_tenant, query_tenant=tenant_id)
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        rotation = await stores.load_rotation(
            session, tenant_id=tenant_id, role=role, scan_id=scan_id
        )
    state = rotation.state() if rotation else {"profile_ids": [], "cursor": 0, "excluded": []}
    return RotationState(role=role, scan_id=scan_id, **state)


@router.post("", response_model=RotationState)
async def set_rotation(
    body: RotationSet,
    _: Annotated[None, Depends(require_admin_mfa_passed)],
    admin_role: Annotated[str, Depends(_admin_role_dep)],
    role_tenant: Annotated[str | None, Depends(_admin_tenant_dep)],
) -> RotationState:
    tenant_id = _require_tenant(body.tenant_id)
    _enforce_rbac(role=admin_role, role_tenant=role_tenant, query_tenant=tenant_id)
    rotation = LLMRotation(body.profile_ids)
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        await stores.save_rotation(
            session,
            tenant_id=tenant_id,
            role=body.role,
            rotation=rotation,
            scan_id=body.scan_id,
        )
        await session.commit()
    state = rotation.state()
    return RotationState(role=body.role, scan_id=body.scan_id, **state)
