"""Engagement manager Admin API (WP A/D) — create / view / revoke engagements.

POST   /api/v1/admin/engagements             — create a signed-engagement envelope
GET    /api/v1/admin/engagements/{id}        — view scope / window / revoked
POST   /api/v1/admin/engagements/{id}/revoke — revoke (append-only; never deleted)

All endpoints are MFA-gated (``require_admin_mfa_passed``). There is no session
principal under the legacy ``X-Admin-Key`` shim, so the operator passes the
tenant explicitly (body for create, ``?tenant_id=`` for read/revoke); the handler
sets it as the RLS tenant (``set_session_tenant``) before touching the row. The
engagement feeds the fail-closed scope gate
(:func:`src.governance.engagement.assert_in_scope`).
"""

from __future__ import annotations

import uuid
from datetime import datetime
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

router = APIRouter(prefix="/admin/engagements", tags=["admin_engagements"])


class EngagementCreate(BaseModel):
    tenant_id: str
    allowed_targets: list[str] = Field(default_factory=list)
    allowed_tenants: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    window_start: datetime | None = None
    window_end: datetime | None = None
    max_rate_per_target: int | None = None
    signature: str | None = None


class EngagementResponse(BaseModel):
    id: str
    tenant_id: str
    allowed_targets: list[str]
    allowed_tenants: list[str]
    allowed_actions: list[str]
    window_start: datetime | None
    window_end: datetime | None
    max_rate_per_target: int | None
    revoked: bool


def _to_response(row) -> EngagementResponse:
    return EngagementResponse(
        id=row.id,
        tenant_id=row.tenant_id,
        allowed_targets=list(row.allowed_targets or []),
        allowed_tenants=list(row.allowed_tenants or []),
        allowed_actions=list(row.allowed_actions or []),
        window_start=row.window_start,
        window_end=row.window_end,
        max_rate_per_target=row.max_rate_per_target,
        revoked=bool(row.revoked),
    )


def _require_tenant(tenant_id: str) -> str:
    """Reject a non-UUID tenant before it reaches the RLS ``SET LOCAL``."""
    try:
        uuid.UUID(str(tenant_id))
    except (ValueError, AttributeError, TypeError) as exc:
        raise HTTPException(status_code=400, detail="invalid tenant_id") from exc
    return tenant_id


@router.post("", response_model=EngagementResponse)
async def create_engagement(
    body: EngagementCreate,
    _: Annotated[None, Depends(require_admin_mfa_passed)],
    role: Annotated[str, Depends(_admin_role_dep)],
    role_tenant: Annotated[str | None, Depends(_admin_tenant_dep)],
) -> EngagementResponse:
    tenant_id = _require_tenant(body.tenant_id)
    _enforce_rbac(role=role, role_tenant=role_tenant, query_tenant=tenant_id)
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        row = await stores.create_engagement(
            session,
            tenant_id=tenant_id,
            allowed_targets=body.allowed_targets,
            allowed_tenants=body.allowed_tenants,
            allowed_actions=body.allowed_actions,
            window_start=body.window_start,
            window_end=body.window_end,
            max_rate_per_target=body.max_rate_per_target,
            signature=body.signature,
        )
        resp = _to_response(row)
        await session.commit()
    return resp


@router.get("/{engagement_id}", response_model=EngagementResponse)
async def get_engagement(
    engagement_id: str,
    _: Annotated[None, Depends(require_admin_mfa_passed)],
    role: Annotated[str, Depends(_admin_role_dep)],
    role_tenant: Annotated[str | None, Depends(_admin_tenant_dep)],
    tenant_id: str = Query(...),
) -> EngagementResponse:
    tenant_id = _require_tenant(tenant_id)
    _enforce_rbac(role=role, role_tenant=role_tenant, query_tenant=tenant_id)
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        row = await stores.get_engagement(session, engagement_id)
        if row is None or row.tenant_id != tenant_id:
            raise HTTPException(status_code=404, detail="engagement not found")
        return _to_response(row)


@router.post("/{engagement_id}/revoke", response_model=EngagementResponse)
async def revoke_engagement(
    engagement_id: str,
    _: Annotated[None, Depends(require_admin_mfa_passed)],
    role: Annotated[str, Depends(_admin_role_dep)],
    role_tenant: Annotated[str | None, Depends(_admin_tenant_dep)],
    tenant_id: str = Query(...),
) -> EngagementResponse:
    tenant_id = _require_tenant(tenant_id)
    _enforce_rbac(role=role, role_tenant=role_tenant, query_tenant=tenant_id)
    async with async_session_factory() as session:
        await set_session_tenant(session, tenant_id)
        row = await stores.get_engagement(session, engagement_id)
        if row is None or row.tenant_id != tenant_id:
            raise HTTPException(status_code=404, detail="engagement not found")
        row = await stores.revoke_engagement(session, engagement_id)
        resp = _to_response(row)
        await session.commit()
    return resp
