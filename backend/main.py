"""ARGUS Backend — FastAPI application.

Phase 2: Core backend with scans, reports, health routers.
Auth middleware ready; tenant-scoped API.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

logger = logging.getLogger(__name__)
from fastapi.middleware.cors import CORSMiddleware
from src.api.routers import (
    admin,
    auth,
    cache,
    findings,
    health,
    intelligence,
    internal_va,
    knowledge,
    metrics,
    reports,
    sandbox,
    scans,
    skills_public,
    tools,
)
from src.api.routers.recon import recon_router
from src.cache.scan_knowledge_base import get_knowledge_base
from src.core.config import settings
from src.core.exception_handlers import register_exception_handlers
from src.core.logging_config import configure_logging
from src.core.security_headers import SecurityHeadersMiddleware

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan — startup/shutdown."""
    configure_logging()
    import subprocess
    try:
        subprocess.run(["alembic", "upgrade", "head"], check=True, timeout=60)
        logger.info("Alembic migrations applied successfully")
    except Exception as e:
        logger.warning("Startup migrations skipped: %s", type(e).__name__, exc_info=False)
    try:
        get_knowledge_base().warm_cache()
    except Exception as e:
        logger.warning(
            "kb_warm_skipped",
            extra={"event": "kb_warm_skipped", "error_type": type(e).__name__},
        )
    yield


app = FastAPI(
    title="ARGUS API",
    version=settings.version,
    docs_url="/api/v1/docs",
    openapi_url="/api/v1/openapi.json",
    lifespan=lifespan,
)

register_exception_handlers(app)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins_list(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(health.router, prefix="/api/v1")
app.include_router(metrics.router)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1")
app.include_router(findings.router, prefix="/api/v1")
app.include_router(reports.router, prefix="/api/v1")
app.include_router(sandbox.router, prefix="/api/v1")
app.include_router(tools.router, prefix="/api/v1")
app.include_router(admin.router, prefix="/api/v1")
app.include_router(cache.router, prefix="/api/v1")
app.include_router(internal_va.router, prefix="/api/v1")
app.include_router(recon_router, prefix="/api/v1")
app.include_router(intelligence.router, prefix="/api/v1")
app.include_router(skills_public.router, prefix="/api/v1")
app.include_router(knowledge.router, prefix="/api/v1")


@app.get("/")
async def root() -> dict:
    """Root redirect/info."""
    return {"service": "ARGUS API", "version": settings.version, "docs": "/api/v1/docs"}
