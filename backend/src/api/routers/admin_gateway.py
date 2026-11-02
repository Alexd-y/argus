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
async def list_providers(
    tenant_id: str = "",  # noqa: ARG001 - FastAPI route signature; param bound by the framework
    _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None,
) -> list[ProviderResponse]:
    from src.llm_gateway.provider_clients import ALIAS_REGISTRY

    providers = []
    for alias, cfg in ALIAS_REGISTRY.items():
        for p in cfg["providers"]:
            providers.append(
                ProviderResponse(
                    id=p["key"],
                    alias=alias,
                    provider_key=p["key"],
                    model=p["model"],
                    role=cfg["role"],
                    cloud_allowed=p.get("cloud_allowed", True),
                    enabled=bool(p.get("base_url")),
                )
            )
    return providers


@router.get("/usage")
async def get_usage_summary(
    tenant_id: str = "",
    scan_id: str = "",
    _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None,
) -> dict[str, Any]:
    from src.llm_gateway.usage_ledger import get_usage_summary

    return get_usage_summary(tenant_id=tenant_id, scan_id=scan_id)


@router.get("/invocations")
async def list_invocations(
    tenant_id: str = "",
    scan_id: str = "",
    limit: int = 50,
    _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None,
) -> list[dict[str, Any]]:
    from src.llm_gateway.usage_ledger import _ledger

    filtered = [
        e
        for e in _ledger
        if (not tenant_id or e.get("tenant_id") == tenant_id)
        and (not scan_id or e.get("scan_id") == scan_id)
    ]
    return filtered[-limit:]


@router.get("/cost-dashboard")
async def cost_dashboard(
    tenant_id: str = "",
    scan_id: str = "",
    _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None,
) -> dict[str, Any]:
    """Consolidated LLM cost view for the admin dashboard (§4).

    Combines the gateway usage summary with the per-role price table and the
    effective phase routing, so the admin panel can show "$/role, model per phase,
    cloud vs local" in one call. Pure reads; no side effects.
    """
    from src.llm_gateway.usage_ledger import get_usage_summary

    usage = get_usage_summary(tenant_id=tenant_id, scan_id=scan_id)

    prices: list[dict[str, Any]] = []
    try:
        from src.llm.model_aliases import get_alias_registry

        for a in get_alias_registry().list_all():
            p = a.providers[0] if a.providers else None
            prices.append(
                {
                    "alias": a.alias,
                    "role": a.role,
                    "model": getattr(p, "model", "") if p else "",
                    "cloud": bool(getattr(p, "cloud_allowed", False)) if p else False,
                    "price_input_per_million_usd": (
                        getattr(p, "price_input_per_million_usd", 0.0) if p else 0.0
                    ),
                    "price_output_per_million_usd": (
                        getattr(p, "price_output_per_million_usd", 0.0) if p else 0.0
                    ),
                }
            )
    except Exception:  # noqa: BLE001 — telemetry view must not fail on a registry hiccup
        prices = []

    routing: dict[str, Any] = {}
    try:
        from src.llm.phase_routing import _load_routes, is_enabled

        if is_enabled():
            routing = {
                ph: {"mode": r.mode, "fallback": r.fallback, "primary_alias": r.primary_alias}
                for ph, r in _load_routes().items()
            }
    except Exception:  # noqa: BLE001
        routing = {}

    return {"usage": usage, "price_table": prices, "phase_routing": routing}
