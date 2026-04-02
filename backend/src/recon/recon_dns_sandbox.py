"""KAL-005 — dnsrecon / fierce / amass (enum) in sandbox during recon; bounded to one apex domain."""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any

from src.core.config import settings
from src.recon.schemas.base import FindingType
from src.recon.mcp.kal_executor import run_kal_mcp_tool
from src.recon.scan_options_kal import scan_kal_flags

logger = logging.getLogger(__name__)

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", re.I)


def _apex_domain(raw: str) -> str:
    d = (raw or "").strip().lower()
    d = d.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    return d.strip(" .") or ""


def _domain_allowed(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False
    return bool(_DOMAIN_RE.match(domain))


def build_dnsrecon_recon_argv(domain: str) -> list[str]:
    if not _domain_allowed(domain):
        return []
    return ["dnsrecon", "-d", domain, "-t", "std"]


def build_fierce_recon_argv(domain: str) -> list[str]:
    if not _domain_allowed(domain):
        return []
    return ["fierce", "-dns", domain]


def build_amass_enum_passive_argv(domain: str) -> list[str]:
    if not _domain_allowed(domain):
        return []
    return ["amass", "enum", "-passive", "-d", domain]


def _subdomain_intel_rows(tool: str, stdout: str, *, domain: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        token = line.split()[0] if line.split() else ""
        tlow = token.lower()
        dlow = domain.lower()
        is_sub = tlow == dlow or tlow.endswith("." + dlow)
        if "." in token and is_sub and tlow not in seen:
            seen.add(tlow)
            rows.append({
                "finding_type": FindingType.CONTENT_ENTRY,
                "value": f"{tool}:subdomain:{token}",
                "data": {
                    "type": "DNS_SUBDOMAIN",
                    "hostname": token,
                    "apex": domain,
                    "cwe_id": "CWE-200",
                    "description": f"{tool} reported hostname under {domain}.",
                },
                "source_tool": tool,
                "confidence": 0.45,
                "cwe_id": "CWE-200",
            })
        if len(rows) >= max(1, int(settings.kal_recon_dns_max_lines)):
            break
    return rows


async def run_recon_dns_sandbox_bundle(
    target: str,
    options: dict[str, Any] | None,
    *,
    tenant_id: str | None,
    scan_id: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Returns (tool_results_for_llm, intel_overlay)."""
    tool_results: dict[str, Any] = {}
    intel: list[dict[str, Any]] = []
    if not settings.sandbox_enabled:
        return tool_results, intel
    flags = scan_kal_flags(options)
    if not flags["recon_dns_enumeration_opt_in"]:
        return tool_results, intel
    domain = _apex_domain(target)
    if not domain:
        return tool_results, intel

    max_domains = max(1, int(settings.kal_recon_dns_max_domains))
    if max_domains < 1:
        return tool_results, intel

    bundles: list[tuple[str, list[str]]] = [
        ("dnsrecon", build_dnsrecon_recon_argv(domain)),
        ("fierce", build_fierce_recon_argv(domain)),
        ("amass", build_amass_enum_passive_argv(domain)),
    ]
    for name, argv in bundles:
        if not argv:
            logger.info("recon_dns_skip", extra={"tool": name, "reason": "empty_argv"})
            continue
        r = await asyncio.to_thread(
            run_kal_mcp_tool,
            category="dns_enumeration",
            argv=argv,
            target=domain,
            tenant_id=tenant_id,
            scan_id=scan_id,
            password_audit_opt_in=False,
        )
        tool_results[name] = r
        if isinstance(r.get("stdout"), str) and r["stdout"].strip():
            intel.extend(_subdomain_intel_rows(name, r["stdout"], domain=domain))
    return tool_results, intel


def dedupe_subdomain_intel_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop duplicate hostnames (case-insensitive), preserve first row per host."""
    seen: set[str] = set()
    out: list[dict[str, Any]] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        data = r.get("data")
        h = ""
        if isinstance(data, dict):
            h = str(data.get("hostname") or "").strip().lower()
        if not h:
            continue
        if h in seen:
            continue
        seen.add(h)
        out.append(r)
    return out
