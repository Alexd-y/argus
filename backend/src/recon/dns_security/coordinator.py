"""DNS-security recon coordinator (Block 2 wiring).

Orchestrates the pure analyzers (DNS records, DNSSEC, SPF/DMARC/DKIM, AXFR,
subdomains, breach) behind an *injected* async command runner so it stays free
of circular imports and is deterministically unit-testable with a fake runner.

The handler layer supplies ``run_cmd`` (a thin adapter over ``execute_command``)
and the analyzers turn tool output into findings + a subdomain list, which
recon threads into the report and the AttackSurface.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from src.recon.dns_security.data_exposure import collect_breach_exposure
from src.recon.dns_security.dns_records import analyze_axfr, analyze_caa
from src.recon.dns_security.dnssec import analyze_dnssec
from src.recon.dns_security.email_auth import analyze_dkim, analyze_dmarc, analyze_spf
from src.recon.dns_security.subdomains import parse_subdomains

logger = logging.getLogger(__name__)

# Async runner: (command, use_sandbox) -> {"stdout": str, "success": bool, ...}
RunCmd = Callable[[str, bool], Awaitable[dict[str, Any]]]

# Commonly-used DKIM selectors probed blind.
_DEFAULT_DKIM_SELECTORS: tuple[str, ...] = (
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "mail",
)


def _stdout(result: Any) -> str:
    if isinstance(result, dict):
        out = result.get("stdout")
        return out if isinstance(out, str) else ""
    return ""


async def collect_dns_security_findings(
    domain: str,
    *,
    run_cmd: RunCmd,
    emails: list[str] | None = None,
    dkim_selectors: tuple[str, ...] = _DEFAULT_DKIM_SELECTORS,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Run all DNS/email-security probes for ``domain``.

    Returns ``(subdomains, findings)``. Never raises: any individual probe
    failure degrades to no data for that check and a debug log. A "missing"
    finding is only emitted when the corresponding probe actually *ran*
    (exit 0 / produced output) — a failed probe (network/timeout) is treated as
    "unknown", not "absent", to avoid false negatives being reported as findings.
    """
    findings: list[dict[str, Any]] = []
    subdomains: list[str] = []

    async def _safe(cmd: str, use_sandbox: bool = False) -> tuple[str, bool]:
        """Return ``(stdout, ok)`` where ok means the probe ran successfully."""
        try:
            result = await run_cmd(cmd, use_sandbox)
        except Exception as exc:  # noqa: BLE001 — a failed probe must not break recon
            logger.debug("dns_probe_failed", extra={"cmd": cmd[:60], "error": str(exc)})
            return "", False
        text = _stdout(result)
        ok = bool(result.get("success", True)) if isinstance(result, dict) else False
        # +short returns empty with exit 0 for a genuinely absent record; that is
        # a successful probe (ok=True, empty text).
        return text, ok

    def _short_records(text: str) -> list[str]:
        return [ln.strip().strip('"') for ln in text.splitlines() if ln.strip()]

    # DNSSEC.
    dnssec_out, dnssec_ok = await _safe(
        f"dig {domain} DNSKEY +dnssec +noall +answer +comments"
    )
    if dnssec_ok:
        findings.extend(analyze_dnssec(domain, dnssec_out))

    # CAA (dedicated query — ANY is unreliable/often refused).
    caa_out, caa_ok = await _safe(f"dig {domain} CAA +short")
    if caa_ok:
        caa_records = {"CAA": _short_records(caa_out)} if caa_out.strip() else {}
        findings.extend(analyze_caa(domain, caa_records))

    # Email auth: SPF (apex TXT), DMARC (_dmarc TXT), DKIM (selector probes).
    txt_out, txt_ok = await _safe(f"dig {domain} TXT +short")
    if txt_ok:
        findings.extend(analyze_spf(domain, _short_records(txt_out)))
    dmarc_out, dmarc_ok = await _safe(f"dig _dmarc.{domain} TXT +short")
    if dmarc_ok:
        findings.extend(analyze_dmarc(domain, _short_records(dmarc_out)))
    dkim_by_selector: dict[str, list[str]] = {}
    dkim_any_ok = False
    for selector in dkim_selectors:
        sel_out, sel_ok = await _safe(f"dig {selector}._domainkey.{domain} TXT +short")
        dkim_any_ok = dkim_any_ok or sel_ok
        dkim_by_selector[selector] = _short_records(sel_out)
    if dkim_any_ok:
        findings.extend(analyze_dkim(domain, dkim_by_selector))

    # AXFR against each nameserver (dedicated NS query).
    ns_out, ns_ok = await _safe(f"dig {domain} NS +short")
    nameservers = [h.rstrip(".") for h in _short_records(ns_out)] if ns_ok else []
    for ns_host in nameservers[:4]:
        if not ns_host:
            continue
        axfr_out, axfr_ok = await _safe(f"dig AXFR {domain} @{ns_host}")
        if axfr_ok:
            findings.extend(analyze_axfr(domain, axfr_out, nameserver=ns_host))

    # Subdomain enumeration (subfinder, sandboxed).
    subfinder_out, _ = await _safe(f"subfinder -silent -d {domain}", True)
    if subfinder_out:
        subdomains = parse_subdomains([subfinder_out], domain)

    # Breach / credential exposure for collected emails (gated on HIBP_API_KEY).
    if emails:
        try:
            findings.extend(await collect_breach_exposure(domain, emails))
        except Exception as exc:  # noqa: BLE001 — HIBP failure must not break recon
            logger.debug("breach_check_failed", extra={"error": str(exc)})

    return subdomains, findings


__all__ = ["collect_dns_security_findings"]
