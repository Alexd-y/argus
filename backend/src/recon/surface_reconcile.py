"""Deterministic recon surface reconciliation (Block 1.1).

``ai_recon`` derives ``assets``/``ports`` purely from the LLM's reading of the
tool-output text. When a port scanner returns empty stdout (observed: naabu
empty on a live HTTPS host) or the LLM simply omits a port, the structured
``ReconOutput`` ends up with ``ports=[]`` and no technologies — even though
:443 clearly answered a TLS probe. That starves every downstream phase.

This module re-derives the surface deterministically from the raw tool-results
dict that ``run_recon`` already holds, independent of the LLM:

* :func:`parse_open_ports` — scan nmap/naabu/httpx/testssl stdout for ports.
* :func:`tls_probe_succeeded` — did a TLS/SSL probe hit :443?
* :func:`parse_technologies` — extract tech names from WhatWeb/httpx output.
* :func:`reconcile_ports` — merge LLM ports with parsed ports, enforce the
  443-on-live-TLS sanity check, and fall back to sensible defaults for a live
  web host so the port set is never empty when the site is reachable.

All functions are pure and unit-tested on fixed stdout samples.
"""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# nmap grepable/normal: "443/tcp open  https"
_NMAP_PORT_RE = re.compile(r"(\d{1,5})/tcp\s+open", re.IGNORECASE)
# naabu default: "host:port" or "1.2.3.4:port" per line
_HOSTPORT_RE = re.compile(r":(\d{1,5})\b")
# httpx: URLs like https://host:8443/ or https://host/
_URL_PORT_RE = re.compile(r"https?://[^\s/:]+:(\d{1,5})", re.IGNORECASE)

_TLS_TOOL_HINTS = ("testssl", "sslscan", "sslyze", "tls_probe", "tls-probe")
_TECH_TOOL_HINTS = ("whatweb", "httpx", "wappalyzer", "webanalyze")

# Common WhatWeb/httpx technology tokens worth surfacing (case-insensitive).
_TECH_TOKENS = (
    "nginx",
    "apache",
    "cloudflare",
    "litespeed",
    "iis",
    "openresty",
    "wordpress",
    "joomla",
    "drupal",
    "php",
    "asp.net",
    "express",
    "react",
    "vue",
    "angular",
    "jquery",
    "bootstrap",
    "laravel",
    "django",
    "flask",
    "tomcat",
    "node.js",
    "varnish",
    "cloudfront",
    "akamai",
    "hsts",
    "http/2",
    "http/3",
)


def _iter_stdout(tool_results: dict[str, Any]):
    """Yield ``(tool_name, stdout_str)`` for each tool result with output."""
    if not isinstance(tool_results, dict):
        return
    for name, res in tool_results.items():
        if not isinstance(res, dict):
            continue
        stdout = res.get("stdout")
        if isinstance(stdout, str) and stdout.strip():
            yield str(name).lower(), stdout


def _valid_port(value: str) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def parse_open_ports(tool_results: dict[str, Any]) -> set[int]:
    """Extract open TCP ports from nmap/naabu/httpx stdout deterministically."""
    ports: set[int] = set()
    for name, stdout in _iter_stdout(tool_results):
        if "nmap" in name:
            for m in _NMAP_PORT_RE.finditer(stdout):
                port = _valid_port(m.group(1))
                if port is not None:
                    ports.add(port)
        if "naabu" in name:
            for line in stdout.splitlines():
                m = _HOSTPORT_RE.search(line.strip())
                if m:
                    port = _valid_port(m.group(1))
                    if port is not None:
                        ports.add(port)
        if "httpx" in name:
            for m in _URL_PORT_RE.finditer(stdout):
                port = _valid_port(m.group(1))
                if port is not None:
                    ports.add(port)
    return ports


def tls_probe_succeeded(tool_results: dict[str, Any]) -> bool:
    """True when a TLS/SSL probe produced output (implies :443 is live)."""
    if not isinstance(tool_results, dict):
        return False
    for name, res in tool_results.items():
        lname = str(name).lower()
        if not isinstance(res, dict):
            continue
        if any(hint in lname for hint in _TLS_TOOL_HINTS) and (
            res.get("success")
            or (isinstance(res.get("stdout"), str) and res["stdout"].strip())
        ):
            return True
    # Textual TLS_PROBE marker anywhere in tool output.
    for _name, stdout in _iter_stdout(tool_results):
        if "tls_probe" in stdout.lower() or ":443" in stdout:
            return True
    return False


def parse_technologies(tool_results: dict[str, Any]) -> list[str]:
    """Extract a de-duplicated, human-readable technology list.

    WhatWeb/httpx output is scanned for known technology tokens so the report's
    ``technologies`` field is populated even when the LLM drops them.
    """
    found: dict[str, None] = {}
    for name, stdout in _iter_stdout(tool_results):
        if not any(hint in name for hint in _TECH_TOOL_HINTS):
            continue
        lower = stdout.lower()
        for token in _TECH_TOKENS:
            if token in lower:
                # Preserve a canonical display form.
                display = token.upper() if token in ("iis", "php", "hsts") else token.title()
                found.setdefault(display, None)
    return list(found.keys())


def _scheme_default_ports(target: str) -> set[int]:
    t = (target or "").lower()
    if t.startswith("https://"):
        return {443}
    if t.startswith("http://"):
        return {80}
    # Bare host: assume standard web ports are worth probing downstream.
    return {443}


def reconcile_ports(
    llm_ports: list[int] | set[int] | None,
    tool_results: dict[str, Any],
    target: str,
    *,
    scan_id: str | None = None,
) -> list[int]:
    """Merge LLM ports with deterministically parsed ports and repair gaps.

    * Union of LLM-reported ports and ports parsed from raw tool output.
    * Sanity check: if a TLS probe succeeded but 443 is absent, that is a
      parsing failure — add 443 and log a WARN (per Block 1.1).
    * Fallback: if the set is still empty for a reachable web host, seed the
      scheme-default port(s) so downstream phases are not starved.
    """
    ports: set[int] = {p for p in (llm_ports or []) if isinstance(p, int) and 1 <= p <= 65535}
    parsed = parse_open_ports(tool_results)
    ports |= parsed

    tls_live = tls_probe_succeeded(tool_results)
    if tls_live and 443 not in ports:
        logger.warning(
            "recon_port_parse_gap_443",
            extra={
                "scan_id": scan_id,
                "reason": "TLS probe succeeded but 443 missing from parsed ports",
                "parsed_ports": sorted(parsed),
            },
        )
        ports.add(443)

    if not ports:
        defaults = _scheme_default_ports(target)
        if tls_live or (target or "").lower().startswith(("http://", "https://")):
            logger.warning(
                "recon_port_scan_empty_fallback",
                extra={"scan_id": scan_id, "fallback_ports": sorted(defaults), "target": target},
            )
            ports |= defaults

    return sorted(ports)


__all__ = [
    "parse_open_ports",
    "parse_technologies",
    "reconcile_ports",
    "tls_probe_succeeded",
]
