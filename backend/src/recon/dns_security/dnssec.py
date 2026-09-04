"""DNSSEC presence/validity analysis (Block 2.2).

Pure analyzer over ``dig +dnssec`` output. When a zone publishes DNSKEY/RRSIG
records (and resolvers set the AD flag), DNSSEC is active; absence means the
zone is unsigned and vulnerable to DNS spoofing/cache poisoning (CWE-350).
"""

from __future__ import annotations

import re
from typing import Any

from src.recon.dns_security import build_dns_finding

_DNSKEY_RE = re.compile(r"\bIN\s+DNSKEY\b", re.IGNORECASE)
_RRSIG_RE = re.compile(r"\bIN\s+RRSIG\b", re.IGNORECASE)
_DS_RE = re.compile(r"\bIN\s+DS\b", re.IGNORECASE)
# "flags: qr rd ra ad" — the AD (authenticated data) flag means the resolver
# validated the DNSSEC chain.
_AD_FLAG_RE = re.compile(r"flags:[^;]*\bad\b", re.IGNORECASE)

_DNSSEC_CWE = "CWE-350"
_DNSSEC_OWASP = "A05:2021-Security Misconfiguration"


def dnssec_signed(dig_dnssec_stdout: str) -> bool:
    """True when the output shows DNSSEC signing material (DNSKEY + RRSIG)."""
    if not isinstance(dig_dnssec_stdout, str):
        return False
    return bool(_DNSKEY_RE.search(dig_dnssec_stdout) and _RRSIG_RE.search(dig_dnssec_stdout))


def analyze_dnssec(domain: str, dig_dnssec_stdout: str) -> list[dict[str, Any]]:
    """Return a finding when ``domain`` is not DNSSEC-signed."""
    stdout = dig_dnssec_stdout if isinstance(dig_dnssec_stdout, str) else ""
    if dnssec_signed(stdout):
        return []

    has_ds = bool(_DS_RE.search(stdout))
    # DS at the parent but no RRSIG/DNSKEY in the zone => broken chain.
    if has_ds:
        description = (
            f"A DS record exists for {domain} at the parent zone but no DNSKEY/RRSIG were "
            "observed — the DNSSEC chain of trust is incomplete/broken, so validation fails."
        )
        title = f"DNSSEC chain broken — {domain}"
        severity = "medium"
    else:
        description = (
            f"{domain} is not DNSSEC-signed (no DNSKEY/RRSIG records). Without DNSSEC, DNS "
            "responses can be spoofed via cache poisoning or on-path tampering."
        )
        title = f"DNSSEC not enabled — {domain}"
        severity = "low"

    return [
        build_dns_finding(
            title=title,
            severity=severity,
            description=description,
            cwe=_DNSSEC_CWE,
            evidence=(stdout[:1000] or f"No DNSKEY/RRSIG in dig +dnssec output for {domain}"),
            remediation=(
                "Enable DNSSEC at your DNS provider (sign the zone) and publish a DS record "
                "at the registrar so the parent zone establishes the chain of trust. Verify "
                f"with: dig +dnssec {domain} DNSKEY  and  dig DS {domain}"
            ),
            source_tool="dnssec",
            vuln_type="dnssec_missing",
            owasp_category=_DNSSEC_OWASP,
        )
    ]


__all__ = ["analyze_dnssec", "dnssec_signed"]
