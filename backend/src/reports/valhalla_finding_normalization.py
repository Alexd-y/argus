"""VH-005 / VH-007 — Valhalla finding display: OWASP 2021 labels, header verification, remediation hints."""

from __future__ import annotations

from urllib.parse import urlparse

# OWASP Top 10:2021 label aligned with internal 2025 A02 (Security Misconfiguration) in Valhalla.
VALHALLA_OWASP_2021_MISCONFIG = "A05:2021"

_HEADER_REMEDIATION = (
    "Prefer a strict Content-Security-Policy (CSP) without unsafe-inline where feasible; use nonces or hashes. "
    "Do not rely on X-XSS-Protection for XSS defense (deprecated; behavior varies by browser). "
    "Enable HSTS on HTTPS with includeSubDomains when all subdomains are TLS-ready, and use preload only after a sustained commitment. "
    "Set X-Frame-Options DENY/SAMEORIGIN or CSP frame-ancestors, X-Content-Type-Options: nosniff, Referrer-Policy, and Permissions-Policy appropriate to the app."
)


def _origin_from_url(url: str) -> str:
    s = (url or "").strip()
    if not s:
        return "https://example.com"
    if "://" not in s:
        s = f"https://{s}"
    try:
        p = urlparse(s)
        if p.netloc:
            return f"{p.scheme or 'https'}://{p.netloc}"
    except Exception:
        pass
    return "https://example.com"


def header_gap_verification_commands(request_url: str) -> list[dict[str, str]]:
    """
    Stack-neutral verification steps for missing / weak HTTP security headers (evidence only).

    Returns dicts: ``{"tool": "curl|openssl|nmap|naabu|whatweb|nikto", "command": "..."}``.
    """
    base = _origin_from_url(request_url)
    host = urlparse(base).netloc or "target.host"
    rows: list[dict[str, str]] = [
        {
            "tool": "curl",
            "command": f'curl -sS -D - -o /dev/null "{base}/" | sed -n "1,40p"',
        },
        {
            "tool": "whatweb",
            "command": f'whatweb -a 1 "{base}/"',
        },
        {
            "tool": "nikto",
            "command": f'nikto -h "{base}" -Tuning 3',
        },
    ]
    if host and host != "target.host":
        rows.insert(
            1,
            {
                "tool": "openssl",
                "command": f"echo | openssl s_client -servername {host} -connect {host}:443 2>/dev/null | openssl x509 -noout -dates -subject -issuer",
            },
        )
        rows.extend(
            [
                {
                    "tool": "nmap",
                    "command": f"nmap -Pn -sV --script ssl-enum-ciphers -p 443 {host}",
                },
                {
                    "tool": "naabu",
                    "command": f"naabu -host {host} -p 80,443 -silent",
                },
            ]
        )
    return rows


def valhalla_header_finding_remediation_text() -> str:
    """Customer-safe remediation for header-gap class (no product-specific web server config unless stack is known)."""
    return _HEADER_REMEDIATION


# --- OWASP 2025 internal id → 2021 display code (single-taxonomy customer text for Valhalla) ---
# Source: OWASP Top 10 mapping 2021 naming used alongside internal 2025 family ids in this codebase.
_2025_TO_2021_CODE: dict[str, str] = {
    "A01": "A01:2021",
    "A02": "A05:2021",
    "A03": "A06:2021",
    "A04": "A02:2021",
    "A05": "A03:2021",
    "A06": "A04:2021",
    "A07": "A07:2021",
    "A08": "A08:2021",
    "A09": "A09:2021",
    "A10": "A10:2021",
}


def owasp_top10_2021_label(internal_2025: str | None) -> str | None:
    """Map internal Top 10:2025 id to customer OWASP Top 10:2021 code string."""
    if not internal_2025 or not isinstance(internal_2025, str):
        return None
    key = internal_2025.strip().upper()[:3]
    if len(key) != 3 or not key.startswith("A"):
        return None
    return _2025_TO_2021_CODE.get(key)
