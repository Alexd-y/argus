"""WhiteRabbitNeo health endpoint — returns WRB status and model info.

GET /api/v1/llm/whiterabbitneo/health
"""

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/llm", tags=["llm"])


class WRBHealthResponse(BaseModel):
    status: str  # available | unavailable | unconfigured
    model: str = "taico-ai/WhiteRabbitNeo-v3-7B"
    provider: str = "whiterabbitneo"
    error: str = ""
    models_count: int = 0


@router.get("/whiterabbitneo/health", response_model=WRBHealthResponse)
async def whiterabbitneo_health() -> WRBHealthResponse:
    from src.llm.whiterabbitneo_adapter import get_whiterabbitneo_adapter

    wrb = get_whiterabbitneo_adapter()
    if not wrb.is_configured:
        return WRBHealthResponse(status="unconfigured")

    try:
        health = await wrb.health_check()
        return WRBHealthResponse(
            status=health.get("status", "unknown"),
            models_count=health.get("models", 0),
        )
    except Exception as exc:
        return WRBHealthResponse(
            status="unavailable",
            error=str(exc),
        )


@router.get("/health/all")
async def all_llm_health() -> dict:
    from src.llm.router import is_llm_available
    from src.llm.whiterabbitneo_adapter import get_whiterabbitneo_adapter

    wrb = get_whiterabbitneo_adapter()
    wrb_status = "available" if wrb.is_configured else "unconfigured"
    cloud_status = "available" if is_llm_available() else "unconfigured"

    return {
        "whiteRabbitNeo": {
            "status": wrb_status,
            "model": "WhiteRabbitNeo/WhiteRabbitNeo-7B-AWQ",
            "local": True,
        },
        "cloud": {
            "status": cloud_status,
            "note": "Cloud LLMs used only as report supplements",
        },
        "routing_mode": "wrb_first" if wrb.is_configured else "cloud_fallback",
    }
