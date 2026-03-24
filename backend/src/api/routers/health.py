"""Health router — GET /health, GET /ready."""

from fastapi import APIRouter
from sqlalchemy import text

from src.api.schemas import HealthResponse, ReadinessResponse
from src.core.config import settings
from src.core.redis_client import redis_ping
from src.db.session import engine
from src.storage.s3 import ensure_bucket

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Health check endpoint per api-contracts."""
    return HealthResponse(status="ok", version=settings.version)


@router.get("/ready", response_model=ReadinessResponse)
async def ready() -> ReadinessResponse:
    """Readiness — DB, Redis, storage connectivity."""
    db_ok = False
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        pass

    redis_ok = redis_ping()
    storage_ok = ensure_bucket() and ensure_bucket(settings.minio_reports_bucket)

    status = "ok" if (db_ok and redis_ok and storage_ok) else "degraded"
    return ReadinessResponse(status=status, database=db_ok, redis=redis_ok, storage=storage_ok)
