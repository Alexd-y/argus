"""Extract Dark Web Monitoring scan flags from persisted options.

Reads the nested ``dark_web`` sub-object (preferred) or legacy flat keys, with
every value defaulting to its safe default (``enabled`` False). Mirrors
``src.recon.scan_options_kal.scan_kal_flags``.
"""

from __future__ import annotations

from typing import Any

_DEFAULT_NETWORKS = ["breach_db", "clearnet_index", "paste", "feed", "repo"]


def scan_dark_web_flags(options: dict[str, Any] | None) -> dict[str, Any]:
    """Return ``{enabled, include_domain_emails, include_findings, networks}``."""

    empty: dict[str, Any] = {
        "enabled": False,
        "include_domain_emails": True,
        "include_findings": True,
        "networks": list(_DEFAULT_NETWORKS),
    }
    if not options or not isinstance(options, dict):
        return dict(empty)

    dark_web = options.get("dark_web")
    source = dark_web if isinstance(dark_web, dict) else options

    networks = source.get("networks")
    if not isinstance(networks, list) or not networks:
        networks = list(_DEFAULT_NETWORKS)
    else:
        networks = [str(n) for n in networks]

    return {
        "enabled": bool(source.get("enabled")),
        "include_domain_emails": bool(source.get("include_domain_emails", True)),
        "include_findings": bool(source.get("include_findings", True)),
        "networks": networks,
    }
