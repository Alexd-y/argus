"""RECON-002 — merge subdomain/host hints from crt.sh, passive tools, and kal_dns_intel."""

from __future__ import annotations

import json
import re
from typing import Any

from src.core.config import settings

_DOMAIN_RE_HOST = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$",
    re.I,
)


def _add_host(hosts: set[str], raw: str, *, apex: str) -> None:
    t = raw.strip().lower().lstrip("*.") if raw else ""
    if not t or "." not in t:
        return
    if not _DOMAIN_RE_HOST.match(t):
        return
    al = apex.lower().strip()
    if t == al or t.endswith("." + al):
        hosts.add(t)


def merge_subdomain_hosts_into_tool_results(tool_results: dict[str, Any], *, domain: str) -> None:
    """Attach ``subdomains_merged`` tool block (JSON list stdout) for LLM context."""
    apex = domain.strip().lower()
    if not apex:
        return
    hosts: set[str] = set()

    crt = tool_results.get("crtsh")
    if isinstance(crt, dict):
        try:
            arr = json.loads(crt.get("stdout") or "[]")
            if isinstance(arr, list):
                for x in arr:
                    if isinstance(x, str):
                        _add_host(hosts, x, apex=apex)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    inv = tool_results.get("subdomain_passive_inventory")
    if isinstance(inv, dict):
        try:
            arr = json.loads(inv.get("stdout") or "[]")
            if isinstance(arr, list):
                for x in arr:
                    if isinstance(x, str):
                        _add_host(hosts, x, apex=apex)
        except (json.JSONDecodeError, TypeError, ValueError):
            pass

    intel = tool_results.get("kal_dns_intel")
    if isinstance(intel, list):
        for row in intel:
            if not isinstance(row, dict):
                continue
            data = row.get("data")
            if isinstance(data, dict):
                h = data.get("hostname")
                if isinstance(h, str):
                    _add_host(hosts, h, apex=apex)

    for name in ("subfinder", "assetfinder", "findomain", "theharvester", "dnsrecon", "fierce", "amass"):
        block = tool_results.get(name)
        if not isinstance(block, dict):
            continue
        stdout = str(block.get("stdout") or "")
        for line in stdout.splitlines():
            tok = line.strip().split()[0] if line.split() else ""
            _add_host(hosts, tok, apex=apex)

    cap = max(1, int(settings.recon_max_subdomains))
    sorted_h = sorted(hosts)[:cap]
    if sorted_h:
        tool_results["subdomains_merged"] = {
            "success": True,
            "stdout": json.dumps(sorted_h),
            "stderr": "",
            "return_code": 0,
            "execution_time": 0.0,
        }
