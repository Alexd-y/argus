"""DNS/email-security analyzers producing pipeline findings (Block 2).

Existing code (``dig_parser``, ``dns_builder``) parses DNS records and detects
the *presence* of SPF/DMARC/DKIM for a markdown summary, but never evaluates
policy strength and never emits findings. This package adds pure analyzers that
turn parsed DNS data into finding dicts (with concrete how-to-fix remediation)
matching the pipeline's finding shape, so they merge into the report alongside
web findings.

Submodules:

* :mod:`email_auth`  — SPF / DMARC / DKIM policy analysis.
* :mod:`dnssec`      — DNSSEC presence/validity.
* :mod:`dns_records` — record enumeration + AXFR zone-transfer probe.
"""

from __future__ import annotations

from typing import Any

# Severity → default CVSS floor for config-class findings (informational base).
_SEVERITY_CVSS: dict[str, float] = {
    "critical": 9.0,
    "high": 7.0,
    "medium": 5.0,
    "low": 3.1,
    "info": 0.0,
}


def build_dns_finding(
    title: str,
    severity: str,
    description: str,
    *,
    cwe: str | None = None,
    evidence: str = "",
    remediation: str = "",
    source_tool: str = "dns_recon",
    vuln_type: str = "dns_misconfiguration",
    owasp_category: str | None = None,
) -> dict[str, Any]:
    """Build a pipeline-compatible finding dict for a DNS/email-security issue.

    The shape mirrors ``_normalize_intel_finding`` output so these findings pass
    the Block 1.2 evidence gate (they always carry evidence + remediation) and
    merge cleanly into ``vuln_analysis`` findings.
    """
    sev = severity.lower().strip()
    if sev not in _SEVERITY_CVSS:
        sev = "info"
    finding: dict[str, Any] = {
        "title": title[:500],
        "severity": sev,
        "description": description[:5000],
        "cvss": _SEVERITY_CVSS[sev],
        "source": "recon",
        "source_tool": source_tool,
        "vuln_type": vuln_type,
        "evidence": evidence[:5000],
        "remediation": remediation[:5000],
    }
    if cwe:
        finding["cwe"] = cwe
    if owasp_category:
        finding["owasp_category"] = owasp_category
    return finding


__all__ = ["build_dns_finding"]
