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

from src.recon.dns_security.dns_records import (
    analyze_axfr,
    analyze_caa,
    parse_dns_records,
)
from src.recon.dns_security.dnssec import analyze_dnssec
from src.recon.dns_security.email_auth import analyze_email_auth
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
    dkim_selectors: tuple[str, ...] = _DEFAULT_DKIM_SELECTORS,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Run all DNS/email-security probes for ``domain``.

    Returns ``(subdomains, findings)``. Never raises: any individual probe
    failure degrades to no data for that check and a debug log.
    """
    findings: list[dict[str, Any]] = []
    subdomains: list[str] = []

    async def _safe(cmd: str, use_sandbox: bool = False) -> str:
        try:
            return _stdout(await run_cmd(cmd, use_sandbox))
        except Exception as exc:  # noqa: BLE001 — a failed probe must not break recon
            logger.debug("dns_probe_failed", extra={"cmd": cmd[:60], "error": str(exc)})
            return ""

    # DNS records (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA) + CAA advisory.
    any_out = await _safe(f"dig {domain} ANY +noall +answer")
    records = parse_dns_records(any_out)
    findings.extend(analyze_caa(domain, records))

    # DNSSEC.
    dnssec_out = await _safe(f"dig {domain} DNSKEY +dnssec +noall +answer +comments")
    findings.extend(analyze_dnssec(domain, dnssec_out))

    # Email auth: SPF (apex TXT), DMARC (_dmarc TXT), DKIM (selector probes).
    txt_out = await _safe(f"dig {domain} TXT +short")
    txt_records = [ln.strip().strip('"') for ln in txt_out.splitlines() if ln.strip()]
    dmarc_out = await _safe(f"dig _dmarc.{domain} TXT +short")
    dmarc_records = [ln.strip().strip('"') for ln in dmarc_out.splitlines() if ln.strip()]
    dkim_by_selector: dict[str, list[str]] = {}
    for selector in dkim_selectors:
        sel_out = await _safe(f"dig {selector}._domainkey.{domain} TXT +short")
        dkim_by_selector[selector] = [
            ln.strip().strip('"') for ln in sel_out.splitlines() if ln.strip()
        ]
    findings.extend(
        analyze_email_auth(
            domain,
            txt_records=txt_records,
            dmarc_txt_records=dmarc_records,
            dkim_records_by_selector=dkim_by_selector,
        )
    )

    # AXFR against each nameserver.
    for ns in records.get("NS", [])[:4]:
        ns_host = ns.split()[-1].rstrip(".") if ns else ""
        if not ns_host:
            continue
        axfr_out = await _safe(f"dig AXFR {domain} @{ns_host}")
        findings.extend(analyze_axfr(domain, axfr_out, nameserver=ns_host))

    # Subdomain enumeration (subfinder, sandboxed).
    subfinder_out = await _safe(f"subfinder -silent -d {domain}", True)
    if subfinder_out:
        subdomains = parse_subdomains([subfinder_out], domain)

    return subdomains, findings


__all__ = ["collect_dns_security_findings"]
