"""Scan-pipeline triggers for Dark Web Monitoring (T1 recon, T2 vuln_analysis).

Both are best-effort: they evaluate the three gates, then enqueue a Celery task
on ``argus.darkweb``. They NEVER raise into the scan pipeline and NEVER block the
phase (the sweep runs asynchronously). If the broker is unavailable the enqueue
failure is logged and the scan proceeds.
"""

from __future__ import annotations

import logging
from typing import Any

from src.intel.dark_web.gates import pipeline_prefilter_allows

logger = logging.getLogger(__name__)


def _domain_from_target(target: str) -> str:
    t = (target or "").strip()
    for prefix in ("https://", "http://"):
        if t.startswith(prefix):
            t = t[len(prefix) :]
    return t.split("/")[0].split(":")[0].strip().lower()


def _emails_from_recon(recon_out: Any, domain: str) -> list[str]:
    tool_results = getattr(recon_out, "tool_results", None)
    if not isinstance(tool_results, dict):
        return []
    try:
        from src.orchestration.handlers import _harvest_emails

        return _harvest_emails(tool_results, domain)
    except Exception:  # noqa: BLE001
        return []


def trigger_recon_sweep(
    *, scan_id: str, tenant_id: str, target: str, options: dict[str, Any] | None, recon_out: Any
) -> dict[str, Any]:
    """T1: enqueue a scan-level DWM sweep over the domain + its emails."""

    try:
        # Prefilter only (global flag + opt-in). Entitlement is resolved
        # server-side in the task (authoritative, fail-closed) — the trigger has
        # no DB session, so it must not assume entitlement either way.
        allowed, status, flags = pipeline_prefilter_allows(options)
        if not allowed:
            logger.info("darkweb_t1_skipped", extra={"scan_id": scan_id, "status": status.value})
            return {"enqueued": False, "status": status.value}
        domain = _domain_from_target(target)
        emails = (
            _emails_from_recon(recon_out, domain)
            if flags.get("include_domain_emails", True)
            else []
        )
        from src.celery.tasks.darkweb_tasks import darkweb_sweep_task

        darkweb_sweep_task.delay(scan_id, tenant_id, domain, emails, options)
        logger.info(
            "darkweb_t1_enqueued",
            extra={"scan_id": scan_id, "domain": domain, "emails": len(emails)},
        )
        return {"enqueued": True, "domain": domain, "emails": len(emails)}
    except Exception:  # noqa: BLE001 - never break the scan pipeline
        logger.exception("darkweb_t1_enqueue_failed", extra={"scan_id": scan_id})
        return {"enqueued": False, "status": "error"}


def trigger_finding_correlation(
    *, scan_id: str, tenant_id: str, target: str, options: dict[str, Any] | None, vuln_out: Any
) -> dict[str, Any]:
    """T2: enqueue a per-finding DWM correlation pass after vuln_analysis."""

    try:
        allowed, status, flags = pipeline_prefilter_allows(options)
        if not allowed or not flags.get("include_findings", True):
            return {"enqueued": False, "status": status.value}
        findings = getattr(vuln_out, "findings", None) or []
        findings = [f for f in findings if isinstance(f, dict)][:50]
        if not findings:
            return {"enqueued": False, "status": "ran_empty"}
        from src.celery.tasks.darkweb_tasks import darkweb_correlate_task

        darkweb_correlate_task.delay(
            scan_id, tenant_id, findings, _domain_from_target(target), options
        )
        logger.info("darkweb_t2_enqueued", extra={"scan_id": scan_id, "findings": len(findings)})
        return {"enqueued": True, "findings": len(findings)}
    except Exception:  # noqa: BLE001
        logger.exception("darkweb_t2_enqueue_failed", extra={"scan_id": scan_id})
        return {"enqueued": False, "status": "error"}


__all__ = ["trigger_finding_correlation", "trigger_recon_sweep"]
