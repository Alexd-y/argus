"""OWASP Top 10:2025 category codes for ``findings.owasp_category``.

Stored values are short ids ``A01``…``A10`` (no year suffix, no slug). Titles below
match OWASP Top 10:2025; see https://owasp.org/Top10/ for authoritative wording.

- A01 — Broken Access Control
- A02 — Security Misconfiguration
- A03 — Software Supply Chain Failures
- A04 — Cryptographic Failures
- A05 — Injection
- A06 — Insecure Design
- A07 — Authentication Failures
- A08 — Software or Data Integrity Failures
- A09 — Security Logging & Alerting Failures
- A10 — Mishandling of Exceptional Conditions
"""

from typing import Literal, cast

OWASP_TOP10_2025_CATEGORY_IDS: tuple[str, ...] = (
    "A01",
    "A02",
    "A03",
    "A04",
    "A05",
    "A06",
    "A07",
    "A08",
    "A09",
    "A10",
)

# Short titles for reports / UI (OWASP Top 10:2025)
OWASP_TOP10_2025_CATEGORY_TITLES: dict[str, str] = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A03": "Software Supply Chain Failures",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A06": "Insecure Design",
    "A07": "Authentication Failures",
    "A08": "Software or Data Integrity Failures",
    "A09": "Security Logging & Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}

OwaspTop102025CategoryId = Literal[
    "A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"
]


def findings_owasp_category_check_sql() -> str:
    """PostgreSQL CHECK expression for nullable ``findings.owasp_category``."""
    inside = ", ".join(f"'{x}'" for x in OWASP_TOP10_2025_CATEGORY_IDS)
    return f"owasp_category IS NULL OR owasp_category IN ({inside})"


def parse_owasp_category(value: str | None) -> OwaspTop102025CategoryId | None:
    """Map DB string to API literal; unknown values become ``None`` (defensive)."""
    if value is None:
        return None
    if value in OWASP_TOP10_2025_CATEGORY_IDS:
        return cast(OwaspTop102025CategoryId, value)
    return None
