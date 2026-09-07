"""XposedOrNot breach-exposure analysis (keyless, alongside HIBP).

Queries the free XposedOrNot API (https://xposedornot.com) for collected emails
and turns hits into a "Data Exposure" finding, mirroring
:mod:`src.recon.dns_security.data_exposure` but for a source that needs no API
key. Emails are masked and only breach *names* are emitted — never passwords or
raw breached values. Gated on ``settings.xposedornot_enabled`` (off by default)
so recon never makes an unexpected external call.

Severity is ``low``: presence of an email in public breach corpora is evidence
of exposure but, unlike HIBP data-classes, does not by itself confirm a
password leak (spec §6: a found public email is not automatically a leak).
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from src.core.config import settings
from src.recon.dns_security import build_dns_finding
from src.recon.dns_security.data_exposure import mask_email

logger = logging.getLogger(__name__)

_CWE = "CWE-359"  # Exposure of Private Personal Information
_OWASP = "A04:2021-Insecure Design"
_XON_CHECK_URL = "https://api.xposedornot.com/v1/check-email/{email}"

EmailBreachFetcher = Callable[[str], Awaitable[list[str]]]


def analyze_xposed_exposure(
    domain: str,
    account_breaches: dict[str, list[str]],
) -> list[dict[str, Any]]:
    """Build a Data Exposure finding from per-email XposedOrNot breach names."""
    exposed = {email: names for email, names in (account_breaches or {}).items() if names}
    if not exposed:
        return []

    sources = sorted(
        {str(n).strip() for names in exposed.values() for n in names if str(n).strip()}
    )
    masked = sorted(mask_email(e) for e in exposed)

    description = (
        f"{len(exposed)} email address(es) associated with {domain} appear in "
        f"{len(sources)} public breach corpus/corpora per XposedOrNot. This indicates "
        "prior exposure that enables credential-stuffing and targeted phishing; it does "
        "not by itself confirm a current password leak."
    )
    evidence = (
        f"Exposed accounts: {', '.join(masked)}\n"
        f"Breach sources: {', '.join(sources) or 'n/a'}\n"
        "Source: XposedOrNot check-email API"
    )
    return [
        build_dns_finding(
            title=f"Email exposed in public breaches (XposedOrNot) — {domain}",
            severity="low",
            description=description,
            cwe=_CWE,
            evidence=evidence,
            remediation=(
                "Rotate and monitor affected accounts, enable MFA, and check for password "
                "reuse across services. Enroll the domain in breach monitoring."
            ),
            source_tool="xposedornot",
            vuln_type="credential_exposure",
            owasp_category=_OWASP,
        )
    ]


async def _default_fetch(email: str) -> list[str]:
    """Fetch breach names for one email from XposedOrNot (keyless)."""
    url = _XON_CHECK_URL.format(email=email)
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, headers={"User-Agent": "argus-recon"})
    if resp.status_code != 200:
        return []
    data = resp.json()
    if not isinstance(data, dict):
        return []
    breaches = data.get("breaches")
    if isinstance(breaches, list) and breaches and isinstance(breaches[0], list):
        return [str(n) for n in breaches[0]]
    return []


async def collect_xposed_exposure(
    domain: str,
    emails: list[str],
    *,
    fetch: EmailBreachFetcher | None = None,
    max_accounts: int = 25,
) -> list[dict[str, Any]]:
    """Query XposedOrNot for ``emails`` and return Data Exposure findings.

    Gated on ``settings.xposedornot_enabled``. ``fetch`` is injectable so unit
    tests never hit the network. Never raises — failures degrade to no finding.
    """
    if not getattr(settings, "xposedornot_enabled", False):
        logger.info("xposed_check_skipped", extra={"reason": "disabled", "domain": domain})
        return []

    fetcher = fetch or _default_fetch
    results: dict[str, list[str]] = {}
    for email in list(dict.fromkeys(e for e in emails if e and "@" in e))[:max_accounts]:
        try:
            names = await fetcher(email)
        except Exception as exc:  # noqa: BLE001 — degrade gracefully, never break recon
            logger.warning("xposed_query_failed", extra={"error": str(exc)})
            continue
        if names:
            results[email] = list(names)
    return analyze_xposed_exposure(domain, results)


__all__ = ["analyze_xposed_exposure", "collect_xposed_exposure"]
