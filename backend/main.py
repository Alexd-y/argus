"""ARGUS Backend — FastAPI application.

Phase 2: Core backend with scans, reports, health routers.
Auth middleware ready; tenant-scoped API.
"""

import logging
import subprocess
from contextlib import asynccontextmanager

from fastapi import FastAPI
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
    mcp_slack_callbacks,
    metrics,
    providers_health,
    queues_health,
    reports,
    sandbox,
    scans,
    skills_public,
    tools,
)
import src.api.routers.admin_audit_chain  # noqa: F401 — admin audit-log chain integrity verify (T25)
import src.api.routers.admin_bulk_ops  # noqa: F401 — side-effect: register bulk routes on admin.router
import src.api.routers.admin_findings  # noqa: F401 — admin cross-tenant findings query (T24)
import src.api.routers.admin_scans  # noqa: F401 — admin scan history + detail routes

from src.api.routers.recon import recon_router
from src.cache.scan_knowledge_base import get_knowledge_base
from src.core.config import settings
from src.core.exception_handlers import register_exception_handlers
from src.core.logging_config import configure_logging
from src.core.metrics_middleware import HttpMetricsMiddleware
from src.core.otel_init import setup_observability, shutdown_observability
from src.core.security_headers import SecurityHeadersMiddleware

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Lifespan — startup/shutdown."""
    configure_logging()
    try:
        setup_observability(_app)
    except Exception as e:
        logger.warning(
            "otel_setup_failed",
            extra={"event": "otel_setup_failed", "error_type": type(e).__name__},
        )
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
    try:
        yield
    finally:
        try:
            shutdown_observability()
        except Exception as e:
            logger.warning(
                "otel_shutdown_failed",
                extra={"event": "otel_shutdown_failed", "error_type": type(e).__name__},
            )


app = FastAPI(
    title="ARGUS API",
    version=settings.version,
    docs_url="/api/v1/docs",
    openapi_url="/api/v1/openapi.json",
    lifespan=lifespan,
)

register_exception_handlers(app)

app.add_middleware(HttpMetricsMiddleware)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins_list(),
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

app.include_router(health.router, prefix="/api/v1")
app.include_router(health.router)
app.include_router(metrics.router)
app.include_router(providers_health.router)
app.include_router(queues_health.router)
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
app.include_router(mcp_slack_callbacks.router, prefix="/api/v1")


@app.get("/")
async def root() -> dict:
    """Root redirect/info."""
    return {"service": "ARGUS API", "version": settings.version, "docs": "/api/v1/docs"}
