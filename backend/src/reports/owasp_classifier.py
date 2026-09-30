"""OWASP Top 10:2021 classifier (formats prompt Phase 7 / C-19).

The category is derived from a finding's CWE (primary) or its confirmation class
(fallback) via an explicit table — never a fuzzy heuristic. TLS/crypto → A02,
configuration/headers → A05, etc. Returns a canonical ``Axx:2021`` code, or ``None``
when the class is genuinely unmapped (the report then prints "не сопоставлено", not a
blank cell).
"""

from __future__ import annotations

import re

_OWASP_TITLES: dict[str, str] = {
    "A01": "A01:2021 — Broken Access Control",
    "A02": "A02:2021 — Cryptographic Failures",
    "A03": "A03:2021 — Injection",
    "A04": "A04:2021 — Insecure Design",
    "A05": "A05:2021 — Security Misconfiguration",
    "A06": "A06:2021 — Vulnerable and Outdated Components",
    "A07": "A07:2021 — Identification and Authentication Failures",
    "A08": "A08:2021 — Software and Data Integrity Failures",
    "A09": "A09:2021 — Security Logging and Monitoring Failures",
    "A10": "A10:2021 — Server-Side Request Forgery (SSRF)",
}

#: CWE (numeric) → OWASP 2021 family. Primary signal.
_CWE_TO_OWASP: dict[int, str] = {
    22: "A01",
    284: "A01",
    285: "A01",
    639: "A01",
    200: "A01",
    352: "A01",
    319: "A02",
    326: "A02",
    327: "A02",
    295: "A02",
    311: "A02",
    916: "A02",
    89: "A03",
    79: "A03",
    77: "A03",
    78: "A03",
    94: "A03",
    611: "A03",
    1021: "A04",
    602: "A04",
    16: "A05",
    693: "A05",
    756: "A05",
    1032: "A05",
    548: "A05",
    937: "A06",
    1035: "A06",
    1104: "A06",
    287: "A07",
    306: "A07",
    307: "A07",
    384: "A07",
    620: "A07",
    502: "A08",
    345: "A08",
    829: "A08",
    117: "A09",
    778: "A09",
    918: "A10",
}

#: confirmation_class → OWASP 2021 family. Fallback when CWE is absent/unknown.
_CLASS_TO_OWASP: dict[str, str] = {
    "sqli": "A03",
    "xss": "A03",
    "cmdi": "A03",
    "rce": "A03",
    "ssrf": "A10",
    "idor": "A01",
    "bola": "A01",
    "auth_bypass": "A07",
    "rate_limiting": "A04",
    "cve_version": "A06",
    "tls_headers": "A02",
}

_CWE_RE = re.compile(r"CWE[-\s]?(\d+)", re.IGNORECASE)


def _cwe_number(cwe: object) -> int | None:
    if cwe is None:
        return None
    m = _CWE_RE.search(str(cwe))
    if m:
        return int(m.group(1))
    try:
        return int(str(cwe).strip())
    except (ValueError, TypeError):
        return None


def classify_owasp(
    cwe: object = None,
    confirmation_class: str | None = None,
    title: str | None = None,
) -> str | None:
    """Return the canonical ``Axx:2021`` code for a finding, or ``None`` if unmapped.

    CWE is the primary signal; the confirmation class is the fallback. TLS/crypto maps
    to A02 and configuration/headers to A05 (the exact mix-up called out in C-19).
    """
    num = _cwe_number(cwe)
    if num is not None and num in _CWE_TO_OWASP:
        return _OWASP_TITLES[_CWE_TO_OWASP[num]]
    if confirmation_class and confirmation_class in _CLASS_TO_OWASP:
        return _OWASP_TITLES[_CLASS_TO_OWASP[confirmation_class]]
    low = (title or "").lower()
    if "tls" in low or "ssl" in low or "cipher" in low or "certificate" in low:
        return _OWASP_TITLES["A02"]
    if "header" in low or "misconfigur" in low or "csp" in low:
        return _OWASP_TITLES["A05"]
    return None


def normalize_owasp_code(value: str | None) -> str | None:
    """Normalise an existing OWASP value to the canonical ``Axx:2021 — Name`` form."""
    if not value:
        return None
    m = re.search(r"A(\d{1,2})", value)
    if not m:
        return value
    key = f"A{int(m.group(1)):02d}"
    return _OWASP_TITLES.get(key, value)


__all__ = ["classify_owasp", "normalize_owasp_code"]
