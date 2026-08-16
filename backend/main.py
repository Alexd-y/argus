"""ARGUS Backend — FastAPI application.

Phase 2: Core backend with scans, reports, health routers.
Auth middleware ready; tenant-scoped API.
"""

import logging
import subprocess
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.api.routers import (
    admin,
    admin_auth,
    admin_password,
    admin_profile,
    auth,
    bounty,
    cache,
    execution_mode,
    findings,
    health,
    intelligence,
    internal_va,
    knowledge,
    mcp_slack_callbacks,
    metrics,
    providers_health,
    queues_health,
    quick,
    reports,
    sandbox,
    scans,
    skills_public,
    tools,
    unified_ai_lab,
    ws,
)
import src.api.routers.admin_audit_chain  # noqa: F401 — admin audit-log chain integrity verify (T25)
import src.api.routers.admin_bulk_ops  # noqa: F401 — side-effect: register bulk routes on admin.router
import src.api.routers.admin_emergency  # noqa: F401 — admin emergency stop / throttle (T31)
import src.api.routers.admin_findings  # noqa: F401 — admin cross-tenant findings query (T24)
import src.api.routers.admin_scans  # noqa: F401 — admin scan history + detail routes
import src.api.routers.admin_reports  # noqa: F401 — admin report list / detail / generate / download
import src.api.routers.admin_password  # noqa: F401 — admin password change / reset
import src.api.routers.admin_schedules  # noqa: F401 — admin scan-schedule CRUD + run-now (T33)
from src.api.admin import mfa as admin_mfa_router  # admin MFA endpoints (C7-T03)
from src.api.routers import admin_webhook_dlq  # admin webhook DLQ list/replay/abandon (T39, ARG-053)
from src.auth.admin_dependencies import log_mfa_enforcement_state

from src.api.routers.llm_health import router as llm_health_router
from src.api.routers.recon import recon_router
from src.api.routers.sandbox_validation import router as sandbox_validation_router
from src.api.routers.web_workbench import web_workbench_router
from src.api.routers.patches import router as patches_router
from src.api.routers.analysis import router as analysis_router
from src.api.routers.binary_triage import router as binary_router
from src.api.routers.incidents import router as incidents_router
from src.api.routers.integrations import router as integrations_router
from src.api.routers.compliance import router as compliance_router
from src.api.routers.admin_gateway import router as admin_gateway_router
from src.api.routers.benchmarks import router as benchmarks_router
from src.api.routers.release import router as release_router
from src.api.routers.research import router as research_router
from src.api.routers.cvss import router as cvss_router
from src.auth.admin_users import bootstrap_admin_user_if_configured
from src.cache.scan_knowledge_base import get_knowledge_base
from src.core.auth import get_required_auth
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
        logger.warning(
            "Startup migrations skipped: %s", type(e).__name__, exc_info=False
        )
    try:
        await bootstrap_admin_user_if_configured()
    except Exception as e:
        logger.warning(
            "admin_bootstrap_skipped",
            extra={
                "event": "argus.auth.admin_bootstrap.skipped",
                "error_type": type(e).__name__,
            },
        )
    try:
        log_mfa_enforcement_state()
    except Exception as e:
        logger.warning(
            "admin_mfa_enforcement_log_failed",
            extra={
                "event": "argus.auth.admin_mfa.enforcement_log_failed",
                "error_type": type(e).__name__,
            },
        )
    try:
        get_knowledge_base().warm_cache()
    except Exception as e:
        logger.warning(
            "kb_warm_skipped",
            extra={"event": "kb_warm_skipped", "error_type": type(e).__name__},
        )
    try:
        if not settings.skip_prompt_verification:
            _verify_prompt_catalog()
        else:
            logger.warning(
                "prompt_catalog_verification_skipped",
                extra={"event": "prompt_catalog.skipped", "reason": "skip_prompt_verification is True"},
            )
    except SystemExit:
        raise
    except Exception as e:
        logger.critical(
            "prompt_catalog_verification_unexpected_error",
            extra={"event": "prompt_catalog.unexpected_error", "error_type": type(e).__name__},
        )
        raise SystemExit(1) from e
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


# ---------------------------------------------------------------------------
# F-M04 — Ed25519 prompt catalog startup verification (fail-closed)
# ---------------------------------------------------------------------------


def _verify_prompt_catalog() -> int:
    """Verify every signed YAML prompt against SIGNATURES at startup.

    Returns the number of verified YAML files on success.
    Raises ``SystemExit(1)`` on any signature mismatch, missing key, or
    missing SIGNATURES file. Verification is skipped when
    ``settings.skip_prompt_verification`` is True.
    """
    from pathlib import Path

    from src.sandbox.signing import KeyManager, KeyNotFoundError, SignatureError, SignaturesFile

    prompts_dir = Path("backend/config/prompts")
    keys_dir = prompts_dir / "_keys"
    signatures_path = prompts_dir / "SIGNATURES"

    logger.info("prompt_catalog_verification_starting")

    if not prompts_dir.is_dir():
        logger.critical(
            "prompt_catalog_verification_failed",
            extra={"event": "prompt_catalog.dir_missing", "path": str(prompts_dir)},
        )
        raise SystemExit(1)

    if not signatures_path.is_file():
        logger.critical(
            "prompt_catalog_verification_failed",
            extra={"event": "prompt_catalog.signatures_missing", "path": str(signatures_path)},
        )
        raise SystemExit(1)

    keys = KeyManager(keys_dir)
    try:
        keys.load()
    except SignatureError as exc:
        logger.critical(
            "prompt_catalog_verification_failed",
            extra={"event": "prompt_catalog.keys_load_error", "reason": str(exc), "keys_dir": str(keys_dir)},
        )
        raise SystemExit(1) from exc

    try:
        signatures = SignaturesFile.from_file(signatures_path)
    except SignatureError as exc:
        logger.critical(
            "prompt_catalog_verification_failed",
            extra={"event": "prompt_catalog.signatures_parse_error", "reason": str(exc)},
        )
        raise SystemExit(1) from exc

    yaml_paths = sorted(p for p in prompts_dir.glob("*.yaml") if p.is_file())

    for yaml_path in yaml_paths:
        rel = yaml_path.relative_to(prompts_dir).as_posix()
        try:
            yaml_bytes = yaml_path.read_bytes()
        except OSError as exc:
            logger.critical(
                "prompt_catalog_verification_failed",
                extra={"event": "prompt_catalog.read_error", "reason": str(exc), "yaml": rel},
            )
            raise SystemExit(1) from exc
        try:
            signatures.verify_one(
                relative_path=rel,
                yaml_bytes=yaml_bytes,
                public_key_resolver=keys.get,
            )
        except (SignatureError, KeyNotFoundError) as exc:
            logger.critical(
                "prompt_catalog_verification_failed",
                extra={"event": "prompt_catalog.signature_mismatch", "reason": str(exc), "yaml": rel},
            )
            raise SystemExit(1) from exc

    logger.info(
        "prompt_catalog_verification_ok",
        extra={"event": "prompt_catalog.verified", "verified_count": len(yaml_paths)},
    )
    return len(yaml_paths)


# ---------------------------------------------------------------------------

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

# SEC-001 — tenant-data planes reject unauthenticated callers. Health, metrics,
# login and admin-session routers are excluded: they are either public probes or
# carry their own admin-session/MFA scheme.
tenant_auth = [Depends(get_required_auth)]

app.include_router(health.router, prefix="/api/v1")
app.include_router(health.router)
app.include_router(metrics.router)
app.include_router(providers_health.router)
app.include_router(queues_health.router)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(admin_auth.router, prefix="/api/v1")
app.include_router(admin_password.router, prefix="/api/v1")
app.include_router(admin_profile.router, prefix="/api/v1")
app.include_router(admin_mfa_router.router, prefix="/api/v1")
app.include_router(scans.router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(quick.router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(execution_mode.router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(unified_ai_lab.nuclei_router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(unified_ai_lab.lab_router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(unified_ai_lab.findings_ext_router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(unified_ai_lab.coverage_router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(unified_ai_lab.api_surface_router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(unified_ai_lab.rag_trace_router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(unified_ai_lab.oast_trace_router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(findings.router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(bounty.router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(cvss_router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(reports.router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(sandbox.router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(tools.router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(admin.router, prefix="/api/v1")
app.include_router(admin_webhook_dlq.router)
app.include_router(cache.router, prefix="/api/v1")
app.include_router(internal_va.router, prefix="/api/v1")
app.include_router(recon_router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(web_workbench_router, prefix="/api/v1", dependencies=tenant_auth)
app.include_router(intelligence.router, prefix="/api/v1")
app.include_router(skills_public.router, prefix="/api/v1")
app.include_router(knowledge.router, prefix="/api/v1")
app.include_router(mcp_slack_callbacks.router, prefix="/api/v1")
app.include_router(llm_health_router, prefix="/api/v1")
app.include_router(sandbox_validation_router, prefix="/api/v1")
app.include_router(patches_router, prefix="/api/v1")
app.include_router(analysis_router, prefix="/api/v1")
app.include_router(binary_router, prefix="/api/v1")
app.include_router(incidents_router, prefix="/api/v1")
app.include_router(integrations_router, prefix="/api/v1")
app.include_router(compliance_router, prefix="/api/v1")
app.include_router(admin_gateway_router, prefix="/api/v1")
app.include_router(benchmarks_router, prefix="/api/v1")
app.include_router(release_router, prefix="/api/v1")
app.include_router(research_router, prefix="/api/v1")
app.include_router(ws.router, prefix="/api/v1")


@app.get("/")
async def root() -> dict:
    """Root redirect/info."""
    return {"service": "ARGUS API", "version": settings.version, "docs": "/api/v1/docs"}
