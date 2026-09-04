"""Breach / credential-exposure analysis (Block 2.5).

Queries HIBP for collected emails (via the existing :class:`HIBPClient`, gated
on ``HIBP_API_KEY``) and turns the results into a single "Data Exposure"
finding. Emails are masked and **no passwords or breached data values are ever
emitted** — only breach counts, source names, and affected data-class labels.
"""

from __future__ import annotations

import logging
from typing import Any

from src.data_sources.hibp_client import HIBPClient
from src.recon.dns_security import build_dns_finding

logger = logging.getLogger(__name__)

_BREACH_CWE = "CWE-359"  # Exposure of Private Personal Information
_BREACH_OWASP = "A04:2021-Insecure Design"
# Data classes that make an exposure materially more dangerous.
_SENSITIVE_CLASSES = {"passwords", "password hints", "security questions and answers"}


def mask_email(email: str) -> str:
    """Mask the local part of an email: ``john.doe@x.com`` -> ``j******e@x.com``."""
    email = (email or "").strip()
    if "@" not in email:
        return "***"
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked = (local[:1] or "*") + "*"
    else:
        masked = f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}"
    return f"{masked}@{domain}"


def analyze_breach_exposure(
    domain: str,
    account_results: dict[str, list[dict[str, Any]]],
) -> list[dict[str, Any]]:
    """Build a Data Exposure finding from per-email HIBP breach lists.

    ``account_results`` maps email -> list of HIBP breach objects (each with
    ``Name`` and ``DataClasses``). Emails with no breaches are ignored.
    """
    exposed: dict[str, list[dict[str, Any]]] = {
        email: breaches
        for email, breaches in (account_results or {}).items()
        if breaches
    }
    if not exposed:
        return []

    breach_names: set[str] = set()
    data_classes: set[str] = set()
    for breaches in exposed.values():
        for b in breaches:
            if not isinstance(b, dict):
                continue
            name = str(b.get("Name") or b.get("name") or "").strip()
            if name:
                breach_names.add(name)
            for dc in b.get("DataClasses") or b.get("data_classes") or []:
                data_classes.add(str(dc).strip())

    has_sensitive = any(dc.lower() in _SENSITIVE_CLASSES for dc in data_classes)
    severity = "medium" if has_sensitive else "low"

    masked = sorted(mask_email(e) for e in exposed)
    sources = sorted(breach_names)
    classes = sorted(data_classes)

    description = (
        f"{len(exposed)} email address(es) associated with {domain} were found in "
        f"{len(sources)} known data breach(es). Exposed credentials enable credential-"
        "stuffing and targeted phishing against the organization."
    )
    if has_sensitive:
        description += " At least one breach exposed passwords or password hints."

    evidence = (
        f"Exposed accounts: {', '.join(masked)}\n"
        f"Breach sources: {', '.join(sources) or 'n/a'}\n"
        f"Affected data classes: {', '.join(classes) or 'n/a'}"
    )

    return [
        build_dns_finding(
            title=f"Exposed credentials / email in known breaches — {domain}",
            severity=severity,
            description=description,
            cwe=_BREACH_CWE,
            evidence=evidence,
            remediation=(
                "Force password resets for affected accounts, enable MFA, and monitor for "
                "credential stuffing. Enroll the domain in breach-monitoring and rotate any "
                "shared/service credentials that may have been reused."
            ),
            source_tool="hibp",
            vuln_type="credential_exposure",
            owasp_category=_BREACH_OWASP,
        )
    ]


async def collect_breach_exposure(
    domain: str,
    emails: list[str],
    *,
    max_accounts: int = 25,
) -> list[dict[str, Any]]:
    """Query HIBP for ``emails`` and return Data Exposure findings.

    Gated on ``HIBP_API_KEY``; returns ``[]`` when the key is absent or no
    breaches are found. Never raises — network/API failures degrade to no
    finding and a structured log entry.
    """
    client = HIBPClient()
    if not client.is_available():
        logger.info("breach_check_skipped", extra={"reason": "hibp_key_absent", "domain": domain})
        return []

    account_results: dict[str, list[dict[str, Any]]] = {}
    for email in list(dict.fromkeys(e for e in emails if e and "@" in e))[:max_accounts]:
        try:
            resp = await client.query(query_type="breachedaccount", account=email)
        except Exception as exc:  # noqa: BLE001 — degrade gracefully, never break recon
            logger.warning("breach_query_failed", extra={"error": str(exc)})
            continue
        if isinstance(resp, dict) and isinstance(resp.get("data"), list):
            account_results[email] = resp["data"]
    return analyze_breach_exposure(domain, account_results)


__all__ = ["analyze_breach_exposure", "collect_breach_exposure", "mask_email"]
