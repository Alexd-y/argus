"""Gateway Admin API — manage providers, view invocations, cost summary.

GET  /api/v1/admin/gateway/providers    — list providers
POST /api/v1/admin/gateway/providers    — create provider
PATCH /api/v1/admin/gateway/providers/{id} — update provider
GET  /api/v1/admin/gateway/usage        — usage summary
GET  /api/v1/admin/gateway/invocations  — invocation history
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from src.auth.admin_dependencies import require_admin_mfa_passed
from src.auth.admin_sessions import SessionPrincipal

router = APIRouter(prefix="/admin/gateway", tags=["admin_gateway"])


class ProviderCreate(BaseModel):
    alias: str
    provider_key: str
    model: str
    base_url: str = ""
    role: str = "planner"
    cloud_allowed: bool = True
    enabled: bool = True
    tenant_id: str = ""


class ProviderResponse(BaseModel):
    id: str
    alias: str
    provider_key: str
    model: str
    role: str
    cloud_allowed: bool
    enabled: bool


@router.get("/providers")
async def list_providers(tenant_id: str = "", _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None) -> list[ProviderResponse]:
    from src.llm_gateway.provider_clients import ALIAS_REGISTRY

    providers = []
    for alias, cfg in ALIAS_REGISTRY.items():
        for p in cfg["providers"]:
            providers.append(ProviderResponse(
                id=p["key"], alias=alias, provider_key=p["key"],
                model=p["model"], role=cfg["role"],
                cloud_allowed=p.get("cloud_allowed", True),
                enabled=bool(p.get("base_url")),
            ))
    return providers


@router.get("/usage")
async def get_usage_summary(
    tenant_id: str = "", scan_id: str = "",
    _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None,
) -> dict[str, Any]:
    from src.llm_gateway.usage_ledger import get_usage_summary
    return get_usage_summary(tenant_id=tenant_id, scan_id=scan_id)


@router.get("/invocations")
async def list_invocations(
    tenant_id: str = "", scan_id: str = "", limit: int = 50,
    _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None,
) -> list[dict[str, Any]]:
    from src.llm_gateway.usage_ledger import _ledger
    filtered = [e for e in _ledger if (not tenant_id or e.get("tenant_id") == tenant_id) and (not scan_id or e.get("scan_id") == scan_id)]
    return filtered[-limit:]
