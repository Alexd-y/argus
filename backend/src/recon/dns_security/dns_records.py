"""DNS record enumeration + AXFR zone-transfer probe (Block 2.1).

Pure parsers over ``dig`` output. ``parse_dns_records`` demuxes an answer
section into a type->values map (A/AAAA/CNAME/MX/NS/TXT/SOA/CAA), and
``analyze_axfr`` detects a successful zone transfer (a high-severity
misconfiguration) plus a missing-CAA advisory.
"""

from __future__ import annotations

import re
from typing import Any

from src.recon.dns_security import build_dns_finding

_ANSWER_LINE_RE = re.compile(
    r"^(?P<domain>\S+?\.?)\s+\d+\s+(?:IN|in)\s+(?P<type>[A-Z]{1,6})\s+(?P<value>.+)$"
)
_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "PTR", "SRV")

# AXFR failure markers emitted by dig when a transfer is refused.
_AXFR_FAIL_MARKERS = (
    "transfer failed",
    "connection refused",
    "communications error",
    "timed out",
    "connection timed out",
    "; failed",
    "no servers could be reached",
    "rcode = refused",
    "; transfer failed",
)

_AXFR_CWE = "CWE-538"
_AXFR_OWASP = "A05:2021-Security Misconfiguration"


def parse_dns_records(dig_stdout: str) -> dict[str, list[str]]:
    """Parse a dig answer section into ``{record_type: [values]}``."""
    records: dict[str, list[str]] = {}
    if not isinstance(dig_stdout, str):
        return records
    for raw in dig_stdout.splitlines():
        line = raw.strip()
        if not line or line.startswith(";"):
            continue
        # Accept answer lines whether or not an explicit ANSWER SECTION header
        # was seen (dig +short / +noall +answer omit section headers).
        match = _ANSWER_LINE_RE.match(line)
        if not match:
            continue
        rtype = match.group("type").upper()
        if rtype not in _RECORD_TYPES:
            continue
        value = match.group("value").strip().strip('"').rstrip(".")
        if not value:
            continue
        bucket = records.setdefault(rtype, [])
        if value not in bucket:
            bucket.append(value)
    return records


def _axfr_succeeded(axfr_stdout: str) -> bool:
    """True when a zone transfer returned zone data instead of being refused."""
    if not isinstance(axfr_stdout, str) or not axfr_stdout.strip():
        return False
    low = axfr_stdout.lower()
    if any(marker in low for marker in _AXFR_FAIL_MARKERS):
        return False
    # A successful AXFR streams the whole zone: SOA present and several records.
    if "in soa" not in low and " soa " not in low:
        return False
    answer_lines = [
        ln for ln in axfr_stdout.splitlines()
        if _ANSWER_LINE_RE.match(ln.strip())
    ]
    return len(answer_lines) >= 2


def analyze_axfr(domain: str, axfr_stdout: str, nameserver: str = "") -> list[dict[str, Any]]:
    """Emit a high-severity finding when ``domain`` allows AXFR zone transfer."""
    if not _axfr_succeeded(axfr_stdout):
        return []
    ns_suffix = f" from {nameserver}" if nameserver else ""
    return [
        build_dns_finding(
            title=f"DNS zone transfer (AXFR) allowed — {domain}",
            severity="high",
            description=(
                f"The nameserver{ns_suffix} allowed a full AXFR zone transfer for {domain}, "
                "exposing the entire DNS zone (all hosts, internal names and infrastructure) "
                "to any unauthenticated client."
            ),
            cwe=_AXFR_CWE,
            evidence=axfr_stdout[:2000],
            remediation=(
                "Restrict zone transfers to authorized secondary nameservers only, e.g. BIND:\n"
                "  allow-transfer { <secondary-ip>; };\n"
                "and deny AXFR from the public internet."
            ),
            source_tool="dig_axfr",
            vuln_type="zone_transfer",
            owasp_category=_AXFR_OWASP,
        )
    ]


def analyze_caa(domain: str, records: dict[str, list[str]]) -> list[dict[str, Any]]:
    """Advisory finding when no CAA record restricts certificate issuance."""
    if records.get("CAA"):
        return []
    return [
        build_dns_finding(
            title=f"No CAA record — {domain}",
            severity="low",
            description=(
                f"{domain} publishes no CAA record, so any public CA may issue certificates "
                "for the domain, widening the mis-issuance attack surface."
            ),
            cwe="CWE-295",
            evidence=f"No CAA record found for {domain}",
            remediation=(
                "Publish a CAA record restricting issuance to your CA, e.g.:\n"
                f'{domain}. IN CAA 0 issue "letsencrypt.org"'
            ),
            source_tool="dns_recon",
            vuln_type="caa_missing",
            owasp_category=_AXFR_OWASP,
        )
    ]


__all__ = ["analyze_axfr", "analyze_caa", "parse_dns_records"]
