"""TLS/SSL finding severity gate (VHL-TLS-001).

Historically a bare TLS probe (``TLS_PROBE`` / testssl fallback) was emitted as a
``medium`` weak-crypto finding (``CWE-326``) even when the probe only proved that
:443 was reachable — no weak protocol, cipher, or known TLS vulnerability was
observed. That fabricates a medium out of a successful, healthy TLS handshake.

This gate is the single choke point that decides whether a TLS/SSL finding is
allowed to carry ``medium``+ severity: it may only do so when the captured
evidence contains a concrete weak-TLS signal (deprecated protocol, weak/insecure
cipher, a named TLS vulnerability, or a certificate error). Otherwise the finding
is capped to ``info`` (a coverage/observation signal, not a vulnerability) and the
misleading weak-crypto CVSS floor is cleared.

Pure/deterministic and unit-testable; applied in the finding post-processing loop
so it covers every TLS producer (recon intel + VA active-scan adapters).
"""

from __future__ import annotations

import re
from typing import Any

# Tools / type tokens that identify a TLS/SSL finding.
_TLS_SOURCE_TOOLS: frozenset[str] = frozenset(
    {"testssl", "testssl.sh", "sslscan", "sslyze", "tls_probe", "tls-probe"}
)
_TLS_TYPE_TOKENS: frozenset[str] = frozenset({"tls_probe", "tls", "ssl", "weak_crypto"})

# Concrete weak-TLS signals. Any hit justifies keeping medium+ severity.
_WEAK_PROTOCOL_RE = re.compile(
    r"\b(ssl\s?v?2|ssl\s?v?3|sslv2|sslv3|tls\s?1\.0|tls\s?1\.1|tlsv1\.0|tlsv1\.1)\b",
    re.IGNORECASE,
)
_WEAK_CIPHER_RE = re.compile(
    r"\b(rc4|3des|des-cbc|\bdes\b|null[-_ ]?cipher|export|anon|md5|"
    r"cbc|sweet32|logjam|freak|beast|weak\s+cipher|insecure\s+cipher|"
    r"deprecated\s+cipher)\b",
    re.IGNORECASE,
)
_TLS_VULN_RE = re.compile(
    r"\b(heartbleed|poodle|beast|freak|logjam|drown|robot|sweet32|"
    r"ccs[-_ ]?injection|ticketbleed|lucky13|breach|crime)\b",
    re.IGNORECASE,
)
_CERT_ERROR_RE = re.compile(
    r"\b(expired|self[-_ ]?signed|self signed|hostname mismatch|name mismatch|"
    r"untrusted|not trusted|revoked|invalid certificate|cert(?:ificate)? (?:error|invalid)|"
    r"chain (?:incomplete|issue)|weak (?:signature|key)|rsa\s*(?:512|1024))\b",
    re.IGNORECASE,
)

# CWEs that assert a weak-crypto vulnerability. When the evidence carries no weak
# signal these are downgraded to a neutral configuration CWE so the finding is not
# rendered as a proven cryptographic weakness.
_WEAK_CRYPTO_CWES: frozenset[str] = frozenset({"CWE-326", "CWE-327", "CWE-757"})
_NEUTRAL_TLS_CWE = "CWE-310"  # Cryptographic Issues (informational observation)

_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _blob(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("title") or ""),
        str(finding.get("description") or ""),
        str(finding.get("cwe") or finding.get("cwe_id") or ""),
    ]
    poc = finding.get("proof_of_concept")
    if isinstance(poc, dict):
        for key in ("protocols", "ciphers", "protocol", "cipher", "vulnerabilities", "finding", "detail"):
            val = poc.get(key)
            if val:
                parts.append(str(val))
    return "\n".join(parts)


def is_tls_finding(finding: dict[str, Any]) -> bool:
    """True when the finding describes a TLS/SSL check (any producer)."""
    source = str(finding.get("source_tool") or finding.get("source") or "").strip().lower()
    if source in _TLS_SOURCE_TOOLS:
        return True
    vtype = str(finding.get("type") or finding.get("vuln_type") or "").strip().lower()
    if vtype in _TLS_TYPE_TOKENS or "tls_probe" in vtype:
        return True
    title = str(finding.get("title") or "").lower()
    return "tls_probe" in title or "ssl/tls" in title


def weak_tls_signal(finding: dict[str, Any]) -> bool:
    """True when the finding's evidence contains a concrete weak-TLS signal."""
    blob = _blob(finding)
    if not blob.strip():
        return False
    return bool(
        _WEAK_PROTOCOL_RE.search(blob)
        or _WEAK_CIPHER_RE.search(blob)
        or _TLS_VULN_RE.search(blob)
        or _CERT_ERROR_RE.search(blob)
    )


def gate_tls_finding(finding: dict[str, Any]) -> bool:
    """Cap a non-evidenced TLS finding to ``info`` (mutates in place).

    Returns True when a downgrade was applied. Non-TLS findings and TLS findings
    that carry a real weak signal are left untouched.
    """
    if not is_tls_finding(finding):
        return False
    if weak_tls_signal(finding):
        return False

    downgraded = False
    severity = str(finding.get("severity") or "info").lower()
    if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER["info"]:
        finding["severity"] = "info"
        downgraded = True

    # Clear the weak-crypto CVSS floor — a healthy handshake is not a scored vuln.
    if finding.get("cvss") is not None:
        finding["cvss"] = None
        downgraded = True

    for cwe_field in ("cwe", "cwe_id"):
        cwe_val = str(finding.get(cwe_field) or "").strip().upper()
        if cwe_val in _WEAK_CRYPTO_CWES:
            finding[cwe_field] = _NEUTRAL_TLS_CWE
            downgraded = True

    if downgraded:
        finding["tls_gate_applied"] = True
    return downgraded


__all__ = ["gate_tls_finding", "is_tls_finding", "weak_tls_signal"]
