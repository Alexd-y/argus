"""Endpoint inventory builder for Stage 1 recon — endpoint_inventory.csv.

Probes standard endpoints (robots.txt, sitemap.xml, security.txt, favicon.ico,
manifest.json) per live host. Stage1 MCP paths are policy-governed and
audit-traced. When MCP is requested, behavior is fail-closed.

Role separation:
- mcp-server-fetch: endpoint discovery for Stage 1 (robots.txt, sitemap, etc.).
- ARGUS MCP (argus_mcp.py): Cursor/agent tools (create_scan, subfinder, httpx).
  ARGUS MCP is stdio-only; backend cannot use it directly. Stage 1 uses mcp-server-fetch.
"""

import csv
import io
import logging
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlparse

import httpx

from src.recon.parsers.http_probe_parser import parse_http_probe

logger = logging.getLogger(__name__)

# Standard endpoints to probe per live host
ENDPOINT_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/favicon.ico",
    "/manifest.json",
]


def extract_live_hosts_from_http_probe(path: str | Path) -> list[str]:
    """Extract unique base URLs (scheme + netloc) from http_probe.csv."""
    rows = parse_http_probe(path)
    seen: set[str] = set()
    result: list[str] = []
    for row in rows:
        url = (row.get("url") or "").strip()
        if not url:
            continue
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            continue
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in seen:
            seen.add(base)
            result.append(base)
    return sorted(result)


def _fetch_endpoint_httpx(url: str, timeout: float = 10.0) -> dict:
    """Fetch URL and return status, content_type, exists. Used when no custom fetch."""
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            resp = client.get(url)
            ct = resp.headers.get("Content-Type", resp.headers.get("content-type", ""))
            return {
                "status": resp.status_code,
                "content_type": ct.split(";")[0].strip() if ct else "",
                "exists": resp.status_code < 400,
                "notes": "",
            }
    except Exception:
        logger.info(
            "endpoint_fetch_httpx_failed",
            extra={"url": url, "error_code": "httpx_fetch_failed"},
        )
        return {
            "status": 0,
            "content_type": "",
            "exists": False,
            "notes": "httpx_fetch_failed",
        }


def build_endpoint_inventory(
    live_hosts: list[str] | None = None,
    http_probe_path: str | Path | None = None,
    fetch_func: Callable[[str], dict] | None = None,
    use_mcp: bool = True,
    timeout: float = 10.0,
) -> str:
    """Build endpoint_inventory.csv for standard endpoints.

    Columns: url, status, content_type, exists, notes.

    Args:
        live_hosts: Base URLs (e.g. https://svalbard.ca).
        http_probe_path: Path to http_probe.csv — base URLs extracted from url column.
        fetch_func: Optional custom fetch(url) -> {status, content_type, exists, notes}.
        use_mcp: When True and fetch_func not provided, use MCP user-fetch for endpoint
                 discovery (robots.txt, sitemap.xml, security.txt, etc.) with fail-closed
                 behavior and policy/audit tracing.
        timeout: Request timeout when using httpx or MCP.

    Returns:
        CSV content for endpoint_inventory.csv.
    """
    if http_probe_path:
        live_hosts = extract_live_hosts_from_http_probe(Path(http_probe_path))
    if not live_hosts:
        live_hosts = []

    if fetch_func is not None:
        fetch = fetch_func
    elif use_mcp:
        from src.recon.mcp.client import get_mcp_fetch_func

        mcp_fetch = get_mcp_fetch_func(timeout, operation="endpoint_extraction")
        if mcp_fetch:
            fetch = mcp_fetch
        else:
            def _fetch_mcp_unavailable(_u: str) -> dict:
                return {
                    "status": 0,
                    "content_type": "",
                    "exists": False,
                    "notes": "mcp_fetch_unavailable",
                }

            fetch = _fetch_mcp_unavailable
    else:

        def _fetch_httpx(u: str) -> dict:
            return _fetch_endpoint_httpx(u, timeout)

        fetch = _fetch_httpx

    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(["url", "status", "content_type", "exists", "notes"])

    for base in live_hosts:
        base = base.rstrip("/")
        for path in ENDPOINT_PATHS:
            url = f"{base}{path}"
            result = fetch(url)
            writer.writerow([
                url,
                result.get("status", ""),
                result.get("content_type", ""),
                "yes" if result.get("exists") else "no",
                result.get("notes", ""),
            ])

    return output.getvalue()
