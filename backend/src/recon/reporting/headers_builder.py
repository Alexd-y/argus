"""Headers and TLS report builders for Stage 1 recon outputs."""

from __future__ import annotations

import csv
import io
import logging
import socket
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

KEY_HEADERS = [
    "Content-Type",
    "Server",
    "X-Powered-By",
    "Cache-Control",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]


def _normalize_headers(headers: dict[str, object]) -> dict[str, str]:
    normalized: dict[str, str] = {}
    for key, value in headers.items():
        normalized[str(key).lower()] = str(value)
    return normalized


def _fetch_headers_httpx(url: str, timeout: float = 10.0) -> dict:
    """Fetch URL and return normalized response metadata."""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            response = client.get(url)
            cookies = response.headers.get_list("set-cookie")
            return {
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "set_cookie_list": cookies,
                "url": str(response.url),
            }
    except Exception as exc:
        logger.info(
            "stage1_headers_fetch_failed",
            extra={"url": url, "error": str(exc)[:120]},
        )
        return {
            "status_code": 0,
            "headers": {},
            "set_cookie_list": [],
            "url": url,
            "error": "headers_fetch_failed",
        }


def _extract_cookie_flags(set_cookie_list: list[str]) -> dict[str, int]:
    counts = {
        "cookie_count": len(set_cookie_list),
        "cookies_httponly": 0,
        "cookies_secure": 0,
        "cookies_samesite": 0,
        "cookies_samesite_strict": 0,
        "cookies_samesite_lax": 0,
        "cookies_samesite_none": 0,
    }
    for cookie in set_cookie_list:
        lowered = cookie.lower()
        if "httponly" in lowered:
            counts["cookies_httponly"] += 1
        if "secure" in lowered:
            counts["cookies_secure"] += 1
        if "samesite" in lowered:
            counts["cookies_samesite"] += 1
        if "samesite=strict" in lowered:
            counts["cookies_samesite_strict"] += 1
        if "samesite=lax" in lowered:
            counts["cookies_samesite_lax"] += 1
        if "samesite=none" in lowered:
            counts["cookies_samesite_none"] += 1
    return counts


def _as_csv(rows: list[dict[str, object]], columns: list[str]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(columns)
    for row in rows:
        writer.writerow([row.get(col, "") for col in columns])
    return out.getvalue()


def _header_score(present_map: dict[str, bool]) -> int:
    return sum(1 for present in present_map.values() if present)


def _collect_headers(
    live_hosts: list[str],
    headers_data: dict[str, dict] | None = None,
    fetch_func: Callable[[str], dict] | None = None,
    timeout: float = 10.0,
) -> list[dict[str, object]]:
    fetch = fetch_func or (lambda u: _fetch_headers_httpx(u, timeout))
    data = headers_data or {}
    rows: list[dict[str, object]] = []

    for base_url in live_hosts:
        entry = data.get(base_url) or fetch(base_url)
        headers_raw = entry.get("headers") or {}
        headers = _normalize_headers(headers_raw if isinstance(headers_raw, dict) else {})

        set_cookie_list = entry.get("set_cookie_list")
        if not isinstance(set_cookie_list, list):
            set_cookie_raw = headers.get("set-cookie", "")
            set_cookie_list = [set_cookie_raw] if set_cookie_raw else []
        set_cookie_list = [str(item) for item in set_cookie_list if str(item).strip()]

        present_map = {
            header: bool(headers.get(header.lower(), "").strip())
            for header in SECURITY_HEADERS
        }
        cookie_flags = _extract_cookie_flags(set_cookie_list)
        score = _header_score(present_map)

        rows.append(
            {
                "host_url": base_url,
                "final_url": str(entry.get("url", base_url)),
                "status_code": int(entry.get("status_code", 0) or 0),
                "security_header_score": score,
                "set_cookie_sample": " | ".join(set_cookie_list[:2])[:180],
                **{f"has_{h.lower().replace('-', '_')}": "yes" if present_map[h] else "no" for h in SECURITY_HEADERS},
                **cookie_flags,
                "evidence_ref": f"header_fetch:{base_url}",
            }
        )
    return rows


def _render_headers_summary(rows: list[dict[str, object]]) -> str:
    total = len(rows)
    if total == 0:
        return "# HTTP Headers Summary\n\nNo live hosts were provided.\n"

    expected_all = set(SECURITY_HEADERS)
    all_present = {
        h: all(str(row.get(f"has_{h.lower().replace('-', '_')}", "no")) == "yes" for row in rows)
        for h in SECURITY_HEADERS
    }
    inconsistent_headers = [h for h in SECURITY_HEADERS if not all_present[h]]

    lines = [
        "# HTTP Headers Summary",
        "",
        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Overview",
        "",
        f"- [Evidence] Analyzed hosts: `{total}`",
        "- [Observation] Header posture score is count of present baseline security headers.",
        (
            f"- [Inference] Inconsistent controls found for: "
            f"`{', '.join(inconsistent_headers) if inconsistent_headers else 'none'}`"
        ),
        "",
        "## Host Posture Comparison",
        "",
        "| Host | Status | Header Score | Cookies | HttpOnly | Secure | SameSite | Evidence |",
        "|------|--------|--------------|---------|----------|--------|----------|----------|",
    ]

    for row in sorted(rows, key=lambda item: int(item.get("security_header_score", 0)), reverse=True):
        lines.append(
            "| {host} | {status} | {score}/{max_score} | {cookies} | {httponly} | {secure} | {samesite} | `{evidence}` |".format(
                host=row.get("host_url", ""),
                status=row.get("status_code", 0),
                score=row.get("security_header_score", 0),
                max_score=len(SECURITY_HEADERS),
                cookies=row.get("cookie_count", 0),
                httponly=row.get("cookies_httponly", 0),
                secure=row.get("cookies_secure", 0),
                samesite=row.get("cookies_samesite", 0),
                evidence=row.get("evidence_ref", ""),
            )
        )

    lines.extend(["", "## Security Header Consistency Matrix", ""])
    lines.append("| Header | Consistency | Missing Hosts |")
    lines.append("|--------|-------------|---------------|")
    for header in SECURITY_HEADERS:
        missing_hosts = [
            str(row.get("host_url", ""))
            for row in rows
            if str(row.get(f"has_{header.lower().replace('-', '_')}", "no")) != "yes"
        ]
        consistency = "consistent" if not missing_hosts else "inconsistent"
        lines.append(
            f"| {header} | {consistency} | {', '.join(missing_hosts) if missing_hosts else 'none'} |"
        )

    lines.extend(["", "## Per-Host Details", ""])
    for row in rows:
        lines.extend(
            [
                f"### {row.get('host_url', '')}",
                "",
                f"- [Evidence] Final URL: `{row.get('final_url', '')}`",
                f"- [Evidence] Status code: `{row.get('status_code', 0)}`",
                f"- [Observation] Security header score: `{row.get('security_header_score', 0)}/{len(expected_all)}`",
                (
                    "- [Observation] Cookie flags:"
                    f" HttpOnly={row.get('cookies_httponly', 0)},"
                    f" Secure={row.get('cookies_secure', 0)},"
                    f" SameSite={row.get('cookies_samesite', 0)}"
                ),
                f"- [Evidence] Set-Cookie sample: `{row.get('set_cookie_sample', '') or 'none'}`",
                "",
            ]
        )

    lines.extend(
        [
            "---",
            "",
            "*Generated by ARGUS Recon. Safe recon only (HTTP metadata + headers).*",
        ]
    )
    return "\n".join(lines)


def build_headers_artifacts(
    live_hosts: list[str],
    headers_data: dict[str, dict] | None = None,
    fetch_func: Callable[[str], dict] | None = None,
    timeout: float = 10.0,
) -> tuple[str, str]:
    rows = _collect_headers(
        live_hosts=live_hosts,
        headers_data=headers_data,
        fetch_func=fetch_func,
        timeout=timeout,
    )
    summary = _render_headers_summary(rows)
    csv_columns = [
        "host_url",
        "final_url",
        "status_code",
        "security_header_score",
        *[f"has_{h.lower().replace('-', '_')}" for h in SECURITY_HEADERS],
        "cookie_count",
        "cookies_httponly",
        "cookies_secure",
        "cookies_samesite",
        "cookies_samesite_strict",
        "cookies_samesite_lax",
        "cookies_samesite_none",
        "set_cookie_sample",
        "evidence_ref",
    ]
    detailed_csv = _as_csv(rows, csv_columns)
    return summary, detailed_csv


def build_headers_summary(
    live_hosts: list[str],
    headers_data: dict[str, dict] | None = None,
    fetch_func: Callable[[str], dict] | None = None,
    timeout: float = 10.0,
) -> str:
    """Backward-compatible wrapper returning markdown summary only."""
    summary, _ = build_headers_artifacts(
        live_hosts=live_hosts,
        headers_data=headers_data,
        fetch_func=fetch_func,
        timeout=timeout,
    )
    return summary


def _extract_tls_info(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, object]:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock, ctx.wrap_socket(
            sock, server_hostname=host
        ) as ssock:
            cert = ssock.getpeercert()
        san = [
            entry[1]
            for entry in cert.get("subjectAltName", [])
            if isinstance(entry, tuple) and len(entry) == 2 and entry[0] == "DNS"
        ]
        issuer_parts = cert.get("issuer", [])
        issuer = ""
        if issuer_parts:
            flattened = []
            for item in issuer_parts:
                if item and isinstance(item, tuple) and item[0]:
                    flattened.append(f"{item[0][0]}={item[0][1]}")
            issuer = ", ".join(flattened)
        return {
            "san": san,
            "issuer": issuer or "unknown",
            "expiry": cert.get("notAfter", "unknown"),
            "subject": cert.get("subject", []),
            "error": "",
        }
    except Exception as exc:
        logger.info(
            "stage1_tls_fetch_failed",
            extra={"host": host, "error": str(exc)[:120]},
        )
        return {
            "san": [],
            "issuer": "unknown",
            "expiry": "unknown",
            "subject": [],
            "error": "tls_fetch_failed",
        }


def get_ssl_cert_entry(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, object] | None:
    """Fetch TLS cert and return SslCertEntry-compatible dict for recon_results.

    Returns dict with common_name, subject_alternative_names, issuer,
    validity_not_before, validity_not_after. Returns None on fetch failure.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock, ctx.wrap_socket(
            sock, server_hostname=host
        ) as ssock:
            cert = ssock.getpeercert()

        san = [
            entry[1]
            for entry in cert.get("subjectAltName", [])
            if isinstance(entry, tuple) and len(entry) == 2 and entry[0] == "DNS"
        ]

        issuer_parts = cert.get("issuer", [])
        issuer = ""
        if issuer_parts:
            flattened = []
            for item in issuer_parts:
                if item and isinstance(item, tuple) and item[0]:
                    flattened.append(f"{item[0][0]}={item[0][1]}")
            issuer = ", ".join(flattened)

        common_name = ""
        for item in cert.get("subject", []):
            if item and isinstance(item, tuple):
                for attr in item:
                    if isinstance(attr, tuple) and len(attr) == 2 and attr[0] == "commonName":
                        common_name = str(attr[1])
                        break
            if common_name:
                break

        if not common_name and san:
            common_name = san[0]

        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")
        try:
            not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z")
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        except (ValueError, TypeError):
            logger.info(
                "stage1_tls_date_parse_failed",
                extra={"host": host, "not_before": str(not_before_str)[:50], "not_after": str(not_after_str)[:50]},
            )
            return None

        return {
            "common_name": common_name or host,
            "subject_alternative_names": san,
            "issuer": issuer or "unknown",
            "validity_not_before": not_before,
            "validity_not_after": not_after,
        }
    except Exception as exc:
        logger.info(
            "stage1_tls_fetch_failed",
            extra={"host": host, "error": str(exc)[:120]},
        )
        return None


def build_tls_summary(
    live_hosts: list[str],
    tls_data: dict[str, dict] | None = None,
) -> str:
    """Build tls_summary.md with SAN/issuer/expiry for HTTPS hosts."""
    lines = [
        "# TLS / Certificate Summary",
        "",
        f"**Generated:** {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "## Overview",
        "",
        f"- [Evidence] Target hosts: `{len(live_hosts)}`",
        "- [Observation] TLS metadata was collected via certificate handshake only.",
        "",
    ]

    fetched = tls_data or {}
    processed = 0
    with_tls = 0

    for url in live_hosts:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        scheme = (parsed.scheme or "").lower()
        if not host:
            continue
        processed += 1
        if scheme != "https":
            lines.extend(
                [
                    f"### {url}",
                    "",
                    "- [Observation] Non-HTTPS endpoint; TLS certificate data not applicable.",
                    "",
                ]
            )
            continue

        info = fetched.get(url) or _extract_tls_info(host)
        with_tls += 1
        san = info.get("san") or []
        san_preview = ", ".join(str(item) for item in san[:8]) if isinstance(san, list) else str(san)
        if isinstance(san, list) and len(san) > 8:
            san_preview += f" ... (+{len(san) - 8})"

        lines.extend(
            [
                f"### {url}",
                "",
                f"- [Evidence] SAN: `{san_preview or 'none'}`",
                f"- [Evidence] Issuer: `{info.get('issuer', 'unknown')}`",
                f"- [Evidence] Expiry: `{info.get('expiry', 'unknown')}`",
                (
                    f"- [Inference] Certificate scope likely {'broad' if isinstance(san, list) and len(san) > 5 else 'narrow'} "
                    "based on SAN cardinality."
                ),
                "",
            ]
        )

    lines.extend(
        [
            "## TLS Coverage",
            "",
            f"- [Evidence] Hosts processed: `{processed}`",
            f"- [Evidence] HTTPS hosts with TLS data: `{with_tls}`",
            "",
            "---",
            "",
            "*Generated by ARGUS Recon. Safe recon only (TLS handshake metadata).*",
        ]
    )
    return "\n".join(lines)
