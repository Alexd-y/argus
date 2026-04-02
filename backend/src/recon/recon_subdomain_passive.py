"""RECON-002 — passive subdomain tools (subfinder, assetfinder, findomain, theHarvester) in sandbox."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
from typing import Any

from src.core.config import settings
from src.recon.mcp.kal_executor import run_kal_mcp_tool
from src.recon.mcp.policy import THEHARVESTER_RECON_B_SOURCES_CAP
from src.recon.recon_dns_sandbox import _apex_domain, _domain_allowed, _subdomain_intel_rows
from src.recon.sandbox_tool_runner import build_sandbox_exec_argv, run_argv_simple_sync
from src.recon.scan_options_kal import scan_kal_flags

logger = logging.getLogger(__name__)

_DOMAIN_RE_HOST = re.compile(
    r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$",
    re.I,
)

def _parse_theharvester_sources_csv(raw: str) -> str:
    picked: list[str] = []
    seen: set[str] = set()
    for part in (raw or "").split(","):
        p = part.strip().lower()
        if p and p in THEHARVESTER_RECON_B_SOURCES_CAP and p not in seen:
            seen.add(p)
            picked.append(p)
    if not picked:
        return "crtsh,anubis,urlscan"
    return ",".join(picked)


def build_subfinder_recon_argv(domain: str) -> list[str]:
    if not _domain_allowed(domain):
        return []
    return ["subfinder", "-d", domain, "-silent", "-nW"]


def build_assetfinder_recon_argv(domain: str) -> list[str]:
    if not _domain_allowed(domain):
        return []
    return ["assetfinder", "--subs-only", domain]


def build_findomain_recon_argv(domain: str) -> list[str]:
    if not _domain_allowed(domain):
        return []
    return ["findomain", "-t", domain, "--quiet"]


def build_theharvester_recon_subdomain_argv(domain: str) -> list[str]:
    if not _domain_allowed(domain):
        return []
    sources = _parse_theharvester_sources_csv(settings.recon_theharvester_sources)
    lim = max(50, min(500, int(settings.recon_theharvester_recon_limit)))
    return [
        "theHarvester",
        "-d",
        domain,
        "-b",
        sources,
        "-l",
        str(lim),
    ]


def probe_binary_available(bin_name: str) -> bool:
    """True if *bin_name* is on PATH in sandbox container or on host."""
    name = (bin_name or "").strip()
    if not name:
        return False
    if settings.sandbox_enabled:
        parts = build_sandbox_exec_argv(
            ["which", name],
            use_sandbox=True,
        )
        r = run_argv_simple_sync(parts, timeout_sec=15.0)
        return bool(r.get("success")) and bool((r.get("stdout") or "").strip())
    return shutil.which(name) is not None


def _lines_to_hosts(stdout: str, *, domain: str) -> set[str]:
    dlow = domain.lower()
    out: set[str] = set()
    cap = max(1, int(settings.recon_max_subdomains))
    for line in (stdout or "").splitlines():
        token = line.strip().split()[0] if line.split() else ""
        token = token.lstrip("*.")
        tlow = token.lower()
        if not token or "." not in token:
            continue
        if tlow == dlow or tlow.endswith("." + dlow):
            if _DOMAIN_RE_HOST.match(tlow):
                out.add(tlow)
        if len(out) >= cap:
            break
    return out


def _timeout_sec() -> float:
    v = getattr(settings, "recon_passive_subdomain_timeout_sec", None)
    if v is not None and int(v) > 0:
        return float(int(v))
    return float(max(1, int(settings.recon_tools_timeout)))


async def run_passive_subdomain_sandbox_bundle(
    target: str,
    options: dict[str, Any] | None,
    *,
    tenant_id: str | None,
    scan_id: str | None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """subfinder / assetfinder / findomain / theHarvester; skip if binary or opt-in missing."""
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

    bundles: list[tuple[str, list[str]]] = [
        ("subfinder", build_subfinder_recon_argv(domain)),
        ("assetfinder", build_assetfinder_recon_argv(domain)),
        ("findomain", build_findomain_recon_argv(domain)),
    ]
    if settings.recon_theharvester_passive_enabled:
        bundles.append(("theharvester", build_theharvester_recon_subdomain_argv(domain)))

    t_out = _timeout_sec()

    async def _run_one(name: str, argv: list[str]) -> None:
        if not argv:
            return
        bin0 = argv[0] if argv else ""
        if not probe_binary_available(bin0):
            logger.info(
                "recon_passive_subdomain_skip",
                extra={"event": "recon_passive_subdomain_skip", "tool": name, "reason": "binary_missing"},
            )
            return
        try:
            r = await asyncio.to_thread(
                run_kal_mcp_tool,
                category="dns_enumeration",
                argv=argv,
                target=domain,
                tenant_id=tenant_id,
                scan_id=scan_id,
                password_audit_opt_in=False,
                timeout_sec=t_out,
            )
        except Exception:
            logger.warning(
                "recon_passive_subdomain_failed",
                extra={"event": "recon_passive_subdomain_failed", "tool": name},
                exc_info=True,
            )
            tool_results[name] = {
                "success": False,
                "stdout": "",
                "stderr": "Execution failed",
                "return_code": -1,
                "execution_time": 0.0,
            }
            return
        tool_results[name] = r
        stdout = str(r.get("stdout") or "")
        if stdout.strip():
            intel.extend(_subdomain_intel_rows(name, stdout, domain=domain))

    await asyncio.gather(*[_run_one(n, a) for n, a in bundles], return_exceptions=True)

    merged_hosts: set[str] = set()
    for name, _argv in bundles:
        res = tool_results.get(name)
        if not isinstance(res, dict):
            continue
        stdout = str(res.get("stdout") or "")
        if stdout.strip():
            merged_hosts |= _lines_to_hosts(stdout, domain=domain)

    if merged_hosts:
        cap = max(1, int(settings.recon_max_subdomains))
        hosts_sorted = sorted(merged_hosts)[:cap]
        tool_results["subdomain_passive_inventory"] = {
            "success": True,
            "stdout": json.dumps(hosts_sorted),
            "stderr": "",
            "return_code": 0,
            "execution_time": 0.0,
        }

    return tool_results, intel
