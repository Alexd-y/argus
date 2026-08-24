"""VHQ-008 — Technology version extractor from JS bundles, HTTP headers, and HTML fingerprints.

Parses response HTML and headers to extract concrete technology versions
for enrichment of outdated components and tech stack tables.
"""

from __future__ import annotations

import re
from typing import Any

logger_for_module = __import__("logging").getLogger(__name__)

_NEXT_BUILD_ID_RE = re.compile(r"/_next/static/([a-zA-Z0-9_-]+)/", re.IGNORECASE)
_NEXT_DATA_VERSION_RE = re.compile(r'"buildId"\s*:\s*"([^"]+)"', re.IGNORECASE)
_REACT_VERSION_RE = re.compile(r"react(?:\.production\.min)?\.js/([\d.]+)", re.IGNORECASE)
_VUE_VERSION_RE = re.compile(r"vue(?:\.runtime)?\.js/([\d.]+)", re.IGNORECASE)
_ANGULAR_VERSION_RE = re.compile(r"angular(?:\.min)?\.js/([\d.]+)", re.IGNORECASE)
_WP_VERSION_RE = re.compile(r"wp-includes/js/wp-embed\.min\.js\?ver=([\d.]+)", re.IGNORECASE)
_BOOTSTRAP_VERSION_RE = re.compile(r"bootstrap(?:\.min)?\.css/([\d.]+)", re.IGNORECASE)
_JQUERY_VERSION_RE = re.compile(r"jquery(?:\.min)?\.js[\?ver=]([\d.]+)", re.IGNORECASE)
_GENERAL_VERSION_RE = re.compile(r"([\w.-]+)/([\d]+\.[\d]+(?:\.[\d]+)?)", re.IGNORECASE)


def extract_nextjs_version(response_html: str) -> str | None:
    """Parse /_next/static/<buildId>/ chunks to infer Next.js version."""
    if not response_html:
        return None
    m = _NEXT_DATA_VERSION_RE.search(response_html)
    if m:
        return m.group(1)
    m = _NEXT_BUILD_ID_RE.search(response_html)
    if m:
        return f"build:{m.group(1)}"
    if "/_next/" in response_html:
        return "detected"
    return None


def extract_framework_versions(response_html: str, headers: dict[str, str] | None = None) -> dict[str, str]:
    """Extract all detectable versions from HTML + headers."""
    versions: dict[str, str] = {}
    html = response_html or ""

    v = extract_nextjs_version(html)
    if v:
        versions["next.js"] = v

    m = _REACT_VERSION_RE.search(html)
    if m:
        versions["react"] = m.group(1)

    m = _VUE_VERSION_RE.search(html)
    if m:
        versions["vue"] = m.group(1)

    m = _ANGULAR_VERSION_RE.search(html)
    if m:
        versions["angular"] = m.group(1)

    m = _WP_VERSION_RE.search(html)
    if m:
        versions["wordpress"] = m.group(1)

    m = _BOOTSTRAP_VERSION_RE.search(html)
    if m:
        versions["bootstrap"] = m.group(1)

    m = _JQUERY_VERSION_RE.search(html)
    if m:
        versions["jquery"] = m.group(1)

    if headers:
        lower = {k.lower(): str(v).strip() for k, v in headers.items()}
        server = lower.get("server", "")
        if server:
            sm = re.search(r"(\S+)/([\d.]+)", server)
            if sm:
                versions[sm.group(1).lower()] = sm.group(2)
            elif "cloudfront" in server.lower():
                versions["cloudfront"] = "detected"
            elif "nginx" in server.lower():
                m2 = re.search(r"nginx/([\d.]+)", server, re.IGNORECASE)
                versions["nginx"] = m2.group(1) if m2 else "detected"
            elif "apache" in server.lower():
                m2 = re.search(r"apache/([\d.]+)", server, re.IGNORECASE)
                versions["apache"] = m2.group(1) if m2 else "detected"

        xpb = lower.get("x-powered-by", "")
        if xpb:
            if "express" in xpb.lower():
                m2 = re.search(r"express\s*/?\s*([\d.]+)", xpb, re.IGNORECASE)
                versions["express"] = m2.group(1) if m2 else "detected"
            elif "next" in xpb.lower():
                m2 = re.search(r"next\.?js\s*/?\s*([\d.]+)", xpb, re.IGNORECASE)
                versions["next.js"] = m2.group(1) if m2 else versions.get("next.js", "detected")
            elif "php" in xpb.lower():
                m2 = re.search(r"php/([\d.]+)", xpb, re.IGNORECASE)
                versions["php"] = m2.group(1) if m2 else "detected"

    return versions


def extract_versions_from_whatweb_plugins(plugins: dict[str, Any]) -> dict[str, str]:
    """Extract version strings from WhatWeb plugin output."""
    versions: dict[str, str] = {}
    if not isinstance(plugins, dict):
        return versions
    for name, pval in plugins.items():
        pname = str(name).strip().lower()
        if not pname:
            continue
        version_str = ""
        if isinstance(pval, dict):
            version_str = str(pval.get("version", "") or "").strip()
        elif isinstance(pval, list):
            for item in pval:
                if isinstance(item, dict):
                    version_str = str(item.get("version", "") or "").strip()
                    if version_str:
                        break
        if not version_str:
            detail = str(pval) if not isinstance(pval, (dict, list)) else ""
            m = re.search(r"[\d]+(?:\.[\d]+){1,3}[a-zA-Z0-9._-]*", detail)
            version_str = m.group(0) if m else ""
        if version_str:
            versions[pname] = version_str
    return versions
