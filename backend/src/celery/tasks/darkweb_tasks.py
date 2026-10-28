"""Celery tasks for Dark Web Monitoring sweeps (argus.darkweb queue).

* ``argus.darkweb.sweep``     — T1: scan-level sweep over the domain + its emails.
* ``argus.darkweb.correlate`` — T2: per-finding correlation after vuln_analysis.

Both open their OWN async DB session (the Celery-task idiom), set the RLS tenant
context, run the coordinator, and commit. They never raise: a failure degrades to
a status dict so the scan pipeline is unaffected.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from src.celery_app import app
from src.db.session import create_task_engine_and_session, set_session_tenant
from src.intel.dark_web.catalog import load_catalog
from src.intel.dark_web.coordinator import run_sweep
from src.intel.dark_web.correlation import correlate_findings
from src.intel.dark_web.entitlement import tenant_has_dwm_entitlement
from src.intel.dark_web.gates import evaluate_dark_web_gate, pipeline_prefilter_allows
from src.intel.dark_web.selectors import build_domain_email_selectors

_logger = logging.getLogger(__name__)


def _is_uuid(value: Any) -> bool:
    try:
        uuid.UUID(str(value))
        return True
    except (ValueError, TypeError):
        return False


@app.task(bind=True, name="argus.darkweb.sweep", max_retries=0)
def darkweb_sweep_task(
    self,  # noqa: ANN001, ARG001 - Celery signature
    scan_id: str,
    tenant_id: str,
    domain: str,
    emails: list[str] | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # Cheap pre-check (global flag + per-scan opt-in) before opening a session.
    pre_allowed, pre_status, flags = pipeline_prefilter_allows(options)
    if not pre_allowed:
        return {"status": pre_status.value, "observations": 0}

    async def runner() -> dict[str, Any]:
        catalog = load_catalog()
        engine, session_factory = create_task_engine_and_session()
        try:
            async with session_factory() as session:
                if _is_uuid(tenant_id):
                    await set_session_tenant(session, tenant_id)
                # AUTHORITATIVE gate: resolve entitlement server-side (fail-closed).
                entitled = await tenant_has_dwm_entitlement(session, tenant_id)
                gate = evaluate_dark_web_gate(options, tenant_entitled=entitled)
                if not gate.allowed:
                    return {"status": gate.status.value, "observations": 0}

                selectors = (
                    build_domain_email_selectors(
                        domain,
                        emails or [],
                        catalog=catalog.selector_rules,
                    )
                    if gate.flags.get("include_domain_emails", True)
                    else []
                )
                if not selectors:
                    return {"status": "ran_empty", "observations": 0}

                report = await run_sweep(
                    session=session,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    selectors=selectors,
                    target=domain,
                    catalog=catalog,
                )
                await session.commit()
                return {
                    "status": report.resolve_status().value,
                    "observations": len(report.observations),
                }
        finally:
            await engine.dispose()

    try:
        return asyncio.run(runner())
    except Exception:  # noqa: BLE001 - never break the pipeline
        _logger.exception("darkweb_sweep_task_failed", extra={"scan_id": scan_id})
        return {"status": "error", "observations": 0}


@app.task(bind=True, name="argus.darkweb.correlate", max_retries=0)
def darkweb_correlate_task(
    self,  # noqa: ANN001, ARG001 - Celery signature
    scan_id: str,
    tenant_id: str,
    findings: list[dict[str, Any]] | None = None,
    target: str = "",
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pre_allowed, pre_status, flags = pipeline_prefilter_allows(options)
    if not pre_allowed or not flags.get("include_findings", True):
        return {"status": pre_status.value, "observations": 0}

    async def runner() -> dict[str, Any]:
        engine, session_factory = create_task_engine_and_session()
        try:
            async with session_factory() as session:
                if _is_uuid(tenant_id):
                    await set_session_tenant(session, tenant_id)
                entitled = await tenant_has_dwm_entitlement(session, tenant_id)
                gate = evaluate_dark_web_gate(options, tenant_entitled=entitled)
                if not gate.allowed:
                    return {"status": gate.status.value, "observations": 0}
                report = await correlate_findings(
                    session=session,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    findings=findings or [],
                    target=target,
                )
                await session.commit()
                return {
                    "status": report.resolve_status().value,
                    "observations": len(report.observations),
                }
        finally:
            await engine.dispose()

    try:
        return asyncio.run(runner())
    except Exception:  # noqa: BLE001
        _logger.exception("darkweb_correlate_task_failed", extra={"scan_id": scan_id})
        return {"status": "error", "observations": 0}
