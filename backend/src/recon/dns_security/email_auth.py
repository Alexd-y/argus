"""SPF / DMARC / DKIM email-authentication analysis (Block 2.3).

Pure analyzers over parsed DNS TXT records. Each returns finding dicts with
concrete how-to-fix remediation (example records), covering the gaps observed
on the alleksy.com scan where email auth was never checked.

References: RFC 7208 (SPF), RFC 7489 (DMARC), RFC 6376 (DKIM).
"""

from __future__ import annotations

import re
from typing import Any

from src.recon.dns_security import build_dns_finding

# --- SPF ------------------------------------------------------------------

_SPF_RE = re.compile(r"^\s*v=spf1\b", re.IGNORECASE)
# The SPF "all" mechanism is a standalone space-delimited token with an optional
# qualifier: -all (fail) / ~all (softfail) / ?all (neutral) / +all|all (pass).
# Matching a whole token avoids false hits on substrings like "install".
_ALL_TOKEN_RE = re.compile(r"^([-~?+]?)all$", re.IGNORECASE)


def _spf_all_qualifier(record: str) -> str | None:
    """Return the qualifier of the terminal 'all' mechanism, or None if absent.

    Scans tokens left-to-right and keeps the last matching 'all' mechanism (the
    terminal one wins per RFC 7208 first-match evaluation semantics).
    """
    qualifier: str | None = None
    for token in record.split():
        m = _ALL_TOKEN_RE.match(token)
        if m:
            qualifier = m.group(1) or "+"
    return qualifier

_SPF_CWE = "CWE-16"
_SPF_OWASP = "A05:2021-Security Misconfiguration"


def _spf_records(txt_records: list[str]) -> list[str]:
    return [r for r in txt_records if isinstance(r, str) and _SPF_RE.match(r.strip())]


def analyze_spf(domain: str, txt_records: list[str]) -> list[dict[str, Any]]:
    """Analyze SPF policy strength for ``domain``."""
    findings: list[dict[str, Any]] = []
    spf = _spf_records(txt_records)

    if not spf:
        findings.append(
            build_dns_finding(
                title=f"SPF record missing — {domain}",
                severity="medium",
                description=(
                    f"No SPF (v=spf1) TXT record was found for {domain}. Without SPF, "
                    "receivers cannot verify which hosts may send mail for the domain, "
                    "enabling email spoofing/phishing."
                ),
                cwe=_SPF_CWE,
                evidence=f"No 'v=spf1' TXT record present for {domain}",
                remediation=(
                    "Publish a strict SPF TXT record, e.g.:\n"
                    f'{domain}. IN TXT "v=spf1 include:_spf.google.com -all"\n'
                    "List every legitimate sending host/include and end with '-all' "
                    "(hard fail) rather than '~all' or '?all'."
                ),
                owasp_category=_SPF_OWASP,
            )
        )
        return findings

    if len(spf) > 1:
        findings.append(
            build_dns_finding(
                title=f"Multiple SPF records — {domain}",
                severity="medium",
                description=(
                    f"{len(spf)} SPF records were found for {domain}. RFC 7208 permits "
                    "exactly one; multiple records cause a permerror and SPF is ignored."
                ),
                cwe=_SPF_CWE,
                evidence=" | ".join(spf)[:1000],
                remediation="Merge into a single 'v=spf1 ... -all' TXT record.",
                owasp_category=_SPF_OWASP,
            )
        )

    record = spf[0]
    qualifier = _spf_all_qualifier(record)

    if qualifier in ("+", ""):
        findings.append(
            build_dns_finding(
                title=f"SPF allows any sender (+all) — {domain}",
                severity="high",
                description=(
                    f"The SPF record for {domain} ends with '+all' (or bare 'all'), which "
                    "authorizes ANY host to send mail as the domain — equivalent to having "
                    "no SPF protection and actively enabling spoofing."
                ),
                cwe=_SPF_CWE,
                evidence=record[:1000],
                remediation="Replace the terminal '+all'/'all' with '-all' (hard fail).",
                owasp_category=_SPF_OWASP,
            )
        )
    elif qualifier in ("~", "?"):
        findings.append(
            build_dns_finding(
                title=f"SPF not enforced ({qualifier}all) — {domain}",
                severity="low",
                description=(
                    f"The SPF record for {domain} uses '{qualifier}all' "
                    f"({'softfail' if qualifier == '~' else 'neutral'}), so unauthorized "
                    "mail is accepted/marked rather than rejected."
                ),
                cwe=_SPF_CWE,
                evidence=record[:1000],
                remediation="Tighten the terminal mechanism to '-all' once senders are confirmed.",
                owasp_category=_SPF_OWASP,
            )
        )
    return findings


# --- DMARC ----------------------------------------------------------------

_DMARC_RE = re.compile(r"v=DMARC1", re.IGNORECASE)
_DMARC_POLICY_RE = re.compile(r"\bp\s*=\s*(none|quarantine|reject)\b", re.IGNORECASE)
_DMARC_RUA_RE = re.compile(r"\brua\s*=", re.IGNORECASE)

_DMARC_CWE = "CWE-16"
_DMARC_OWASP = "A05:2021-Security Misconfiguration"


def analyze_dmarc(domain: str, dmarc_txt_records: list[str]) -> list[dict[str, Any]]:
    """Analyze DMARC policy at ``_dmarc.<domain>``."""
    findings: list[dict[str, Any]] = []
    dmarc = [r for r in dmarc_txt_records if isinstance(r, str) and _DMARC_RE.search(r)]

    if not dmarc:
        findings.append(
            build_dns_finding(
                title=f"DMARC record missing — {domain}",
                severity="medium",
                description=(
                    f"No DMARC (v=DMARC1) record was found at _dmarc.{domain}. Without DMARC, "
                    "SPF/DKIM alignment is not enforced and spoofed mail is not reported."
                ),
                cwe=_DMARC_CWE,
                evidence=f"No 'v=DMARC1' TXT record at _dmarc.{domain}",
                remediation=(
                    "Publish a DMARC record, starting in monitor mode then tightening:\n"
                    f'_dmarc.{domain}. IN TXT "v=DMARC1; p=reject; rua=mailto:dmarc@{domain}; '
                    'adkim=s; aspf=s"'
                ),
                owasp_category=_DMARC_OWASP,
            )
        )
        return findings

    record = dmarc[0]
    policy_match = _DMARC_POLICY_RE.search(record)
    policy = policy_match.group(1).lower() if policy_match else None

    if policy == "none":
        findings.append(
            build_dns_finding(
                title=f"DMARC policy is monitor-only (p=none) — {domain}",
                severity="medium",
                description=(
                    f"The DMARC record for {domain} uses 'p=none', which only monitors and "
                    "does not quarantine or reject spoofed mail."
                ),
                cwe=_DMARC_CWE,
                evidence=record[:1000],
                remediation="After validating reports, move to 'p=quarantine' then 'p=reject'.",
                owasp_category=_DMARC_OWASP,
            )
        )
    if not _DMARC_RUA_RE.search(record):
        findings.append(
            build_dns_finding(
                title=f"DMARC has no aggregate reporting (rua) — {domain}",
                severity="low",
                description=(
                    f"The DMARC record for {domain} defines no 'rua=' address, so aggregate "
                    "reports are not collected and misconfigurations go unnoticed."
                ),
                cwe=_DMARC_CWE,
                evidence=record[:1000],
                remediation=f"Add 'rua=mailto:dmarc@{domain}' to the DMARC record.",
                owasp_category=_DMARC_OWASP,
            )
        )
    return findings


# --- DKIM -----------------------------------------------------------------

_DKIM_RE = re.compile(r"v=DKIM1|k=rsa|p=[A-Za-z0-9+/]{40,}", re.IGNORECASE)
_DKIM_CWE = "CWE-16"
_DKIM_OWASP = "A05:2021-Security Misconfiguration"


def analyze_dkim(
    domain: str,
    dkim_records_by_selector: dict[str, list[str]] | None,
) -> list[dict[str, Any]]:
    """Analyze DKIM presence across probed selectors.

    ``dkim_records_by_selector`` maps selector -> TXT records at
    ``<selector>._domainkey.<domain>``. If none of the probed selectors expose a
    valid DKIM key, a low-severity finding is emitted (DKIM cannot be fully
    enumerated blind, so absence is advisory rather than conclusive).
    """
    findings: list[dict[str, Any]] = []
    selectors = dkim_records_by_selector or {}
    has_valid = any(
        any(isinstance(r, str) and _DKIM_RE.search(r) for r in records)
        for records in selectors.values()
    )
    if selectors and not has_valid:
        probed = ", ".join(sorted(selectors.keys()))
        findings.append(
            build_dns_finding(
                title=f"DKIM not detected — {domain}",
                severity="low",
                description=(
                    f"No valid DKIM key (v=DKIM1) was found for {domain} across the probed "
                    f"selectors ({probed}). DKIM signing protects message integrity and is "
                    "required for strict DMARC alignment."
                ),
                cwe=_DKIM_CWE,
                evidence=f"Probed selectors without DKIM: {probed}",
                remediation=(
                    "Enable DKIM signing in your mail provider and publish the public key, e.g.:\n"
                    f'<selector>._domainkey.{domain}. IN TXT "v=DKIM1; k=rsa; p=<base64-public-key>"'
                ),
                owasp_category=_DKIM_OWASP,
            )
        )
    return findings


def analyze_email_auth(
    domain: str,
    *,
    txt_records: list[str] | None = None,
    dmarc_txt_records: list[str] | None = None,
    dkim_records_by_selector: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    """Run SPF + DMARC + DKIM analysis and return the combined findings."""
    findings: list[dict[str, Any]] = []
    findings.extend(analyze_spf(domain, txt_records or []))
    findings.extend(analyze_dmarc(domain, dmarc_txt_records or []))
    findings.extend(analyze_dkim(domain, dkim_records_by_selector))
    return findings


__all__ = [
    "analyze_dkim",
    "analyze_dmarc",
    "analyze_email_auth",
    "analyze_spf",
]
