"""LLM Gateway Health endpoints."""

from fastapi import APIRouter

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict:
    return {"status": "ok", "service": "argus-llm-gateway"}


@router.get("/ready")
async def ready() -> dict:
    return {"status": "ready"}


@router.get("/metrics")
async def metrics() -> dict:
    return {"requests_total": 0, "tokens_total": 0}


@router.get("/providers/health")
async def providers_health() -> dict:
    from src.llm_gateway.provider_clients import ALIAS_REGISTRY

    providers = {}
    for alias, cfg in ALIAS_REGISTRY.items():
        for p in cfg["providers"]:
            key = p["key"]
            if key not in providers:
                providers[key] = {
                    "key": key,
                    "model": p["model"],
                    "cloud": p.get("cloud_allowed", True),
                    "status": "configured" if p.get("base_url") else "unconfigured",
                }
    return {"providers": list(providers.values())}
