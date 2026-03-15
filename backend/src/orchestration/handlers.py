"""Phase handlers — production implementation with real tools and data sources."""

import asyncio
import ipaddress
import json
import logging
import socket
from typing import Any

from src.data_sources.crtsh_client import CrtShClient
from src.data_sources.nvd_client import NVDClient
from src.data_sources.shodan_client import ShodanClient
from src.orchestration.ai_prompts import (
    ai_exploitation,
    ai_post_exploitation,
    ai_recon,
    ai_reporting,
    ai_threat_modeling,
    ai_vuln_analysis,
)
from src.orchestration.exploit_verify import verify_exploit_poc
from src.orchestration.phases import (
    ExploitationInput,
    ExploitationOutput,
    PostExploitationInput,
    PostExploitationOutput,
    ReconInput,
    ReconOutput,
    ReportingInput,
    ReportingOutput,
    ThreatModelInput,
    ThreatModelOutput,
    VulnAnalysisInput,
    VulnAnalysisOutput,
)
from src.tools.executor import execute_command

logger = logging.getLogger(__name__)


def _resolve_ip(domain: str) -> str | None:
    """Resolve domain to IP for Shodan lookup."""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _safe_json(obj: Any, max_len: int = 30000) -> str:
    """Serialize object to JSON string, truncated to max_len."""
    try:
        text = json.dumps(obj, default=str, ensure_ascii=False)
    except (TypeError, ValueError):
        text = str(obj)
    if len(text) > max_len:
        text = text[:max_len] + "\n... [truncated]"
    return text


def _format_tool_results(results: dict[str, Any]) -> str:
    """Format tool results dict into a readable string for LLM."""
    parts: list[str] = []
    for tool_name, result in results.items():
        parts.append(f"--- {tool_name.upper()} ---")
        if isinstance(result, dict):
            stdout = result.get("stdout", "")
            stderr = result.get("stderr", "")
            if stdout:
                parts.append(stdout[:15000])
            if stderr and not result.get("success", True):
                parts.append(f"[stderr] {stderr[:2000]}")
        elif isinstance(result, str):
            parts.append(result[:15000])
        else:
            parts.append(_safe_json(result, 15000))
        parts.append("")
    return "\n".join(parts)


async def _run_nmap(target: str, ports: str = "1-1000") -> dict[str, Any]:
    """Run nmap service/version scan. Tools installed in backend container."""
    cmd = f"nmap -sV -sC -T4 --open -p {ports} {target}"
    logger.info("Running nmap: %s", cmd)
    return execute_command(cmd, use_sandbox=False)


async def _run_dig(domain: str) -> dict[str, Any]:
    """Run dig for DNS records."""
    cmd = f"dig {domain} ANY +noall +answer"
    logger.info("Running dig: %s", cmd)
    return execute_command(cmd, use_sandbox=False)


async def _run_whois(domain: str) -> dict[str, Any]:
    """Run whois lookup."""
    cmd = f"whois {domain}"
    logger.info("Running whois: %s", cmd)
    return execute_command(cmd, use_sandbox=False)


async def _query_crtsh(domain: str) -> dict[str, Any]:
    """Query crt.sh for certificate transparency subdomains."""
    try:
        client = CrtShClient()
        data = await client.query(params={"q": f"%.{domain}"})
        subdomains: set[str] = set()
        for entry in data.get("results", []):
            name = entry.get("name_value", "")
            for line in name.split("\n"):
                line = line.strip().lstrip("*.")
                if line and "." in line:
                    subdomains.add(line)
        return {"success": True, "stdout": json.dumps(sorted(subdomains))}
    except Exception:
        logger.exception("crt.sh query failed")
        return {"success": False, "stdout": "", "stderr": "crt.sh query failed"}


async def _query_shodan(target: str) -> dict[str, Any]:
    """Query Shodan for host information."""
    client = ShodanClient()
    if not client.is_available():
        return {"success": False, "stdout": "", "stderr": "Shodan API key not configured"}

    ip = target if _is_ip(target) else _resolve_ip(target)
    if not ip:
        return {"success": False, "stdout": "", "stderr": f"Cannot resolve {target} to IP"}

    try:
        data = await client.query(endpoint=f"shodan/host/{ip}")
        return {"success": True, "stdout": _safe_json(data, 15000)}
    except Exception:
        logger.exception("Shodan query failed")
        return {"success": False, "stdout": "", "stderr": "Shodan query failed"}


async def run_recon(target: str, options: dict) -> ReconOutput:
    """
    Production recon: nmap + dig + whois + crt.sh + Shodan -> LLM analysis.
    Runs tools in parallel, collects results, feeds to LLM for structured output.
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    ports = options.get("ports", "1-1000")

    nmap_task = _run_nmap(domain, ports)
    dig_task = _run_dig(domain)
    whois_task = _run_whois(domain)
    crtsh_task = _query_crtsh(domain)
    shodan_task = _query_shodan(domain)

    results = await asyncio.gather(
        nmap_task, dig_task, whois_task, crtsh_task, shodan_task,
        return_exceptions=True,
    )

    tool_results: dict[str, Any] = {}
    tool_names = ["nmap", "dig", "whois", "crtsh", "shodan"]
    for name, result in zip(tool_names, results):
        if isinstance(result, Exception):
            logger.warning("Tool %s failed: %s", name, result)
            tool_results[name] = {"success": False, "stdout": "", "stderr": str(result)}
        else:
            tool_results[name] = result

    tool_results_str = _format_tool_results(tool_results)
    logger.info("Recon tool results collected (%d chars), sending to LLM", len(tool_results_str))

    inp = ReconInput(target=target, options=options)
    return await ai_recon(inp, tool_results=tool_results_str)


async def _query_nvd_for_technologies(assets: list[str]) -> str:
    """Query NVD for CVEs related to technologies found in assets."""
    client = NVDClient()
    all_cves: list[dict[str, Any]] = []
    keywords_seen: set[str] = set()

    for asset in assets[:10]:
        parts = asset.lower().split()
        for keyword in parts:
            if len(keyword) < 3 or keyword in keywords_seen:
                continue
            if keyword in ("tcp", "udp", "open", "port", "http", "https", "the", "and", "for"):
                continue
            keywords_seen.add(keyword)

    for keyword in list(keywords_seen)[:5]:
        try:
            data = await client.query(
                params={"keywordSearch": keyword, "resultsPerPage": 5}
            )
            vulns = data.get("vulnerabilities", [])
            for v in vulns[:5]:
                cve_item = v.get("cve", {})
                cve_id = cve_item.get("id", "")
                descriptions = cve_item.get("descriptions", [])
                desc = next(
                    (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
                    "",
                )
                metrics = cve_item.get("metrics", {})
                cvss_data = metrics.get("cvssMetricV31", [{}])
                base_score = (
                    cvss_data[0].get("cvssData", {}).get("baseScore", 0.0)
                    if cvss_data
                    else 0.0
                )
                all_cves.append({
                    "cve_id": cve_id,
                    "description": desc[:500],
                    "base_score": base_score,
                    "keyword": keyword,
                })
        except Exception:
            logger.warning("NVD query for '%s' failed", keyword)

    return _safe_json(all_cves, 20000) if all_cves else "No CVE data available"


async def run_threat_modeling(assets: list[str]) -> ThreatModelOutput:
    """Production threat modeling: NVD CVE lookup + LLM analysis."""
    nvd_data = await _query_nvd_for_technologies(assets)
    logger.info("NVD data collected (%d chars), sending to LLM for threat modeling", len(nvd_data))

    inp = ThreatModelInput(assets=assets)
    return await ai_threat_modeling(inp, nvd_data=nvd_data)


async def run_vuln_analysis(
    threat_model: dict, assets: list[str]
) -> VulnAnalysisOutput:
    """Production vuln analysis: LLM analyzes real threat model and assets."""
    inp = VulnAnalysisInput(threat_model=threat_model, assets=assets)
    return await ai_vuln_analysis(inp)


async def run_exploit_attempt(findings: list[dict]) -> ExploitationOutput:
    """Exploitation: LLM plans theoretical exploit paths based on real findings."""
    inp = ExploitationInput(findings=findings)
    return await ai_exploitation(inp)


async def run_exploit_verify(candidates_output: ExploitationOutput) -> ExploitationOutput:
    """
    EXPLOIT_VERIFY sub-phase: PoC verification of exploit candidates.
    Only candidates that pass verification are returned as verified exploits.
    """
    verified_exploits: list[dict] = []
    verified_finding_ids: set[str] = set()

    for candidate in candidates_output.exploits:
        if verify_exploit_poc(candidate):
            verified = {**candidate, "status": "verified"}
            verified_exploits.append(verified)
            verified_finding_ids.add(str(candidate.get("finding_id", "")))

    verified_evidence = [
        ev
        for ev in candidates_output.evidence
        if not ev.get("finding_id") or str(ev.get("finding_id", "")) in verified_finding_ids
    ]

    return ExploitationOutput(
        exploits=verified_exploits,
        evidence=verified_evidence,
    )


async def run_exploitation(findings: list[dict]) -> ExploitationOutput:
    """
    Exploitation: input(findings) -> output(exploits, evidence).
    Runs EXPLOIT_ATTEMPT then EXPLOIT_VERIFY; only verified exploits are returned.
    """
    attempt_out = await run_exploit_attempt(findings)
    return await run_exploit_verify(attempt_out)


async def run_post_exploitation(
    exploits: list[dict],
) -> PostExploitationOutput:
    """Post exploitation: LLM analyzes lateral movement and persistence."""
    inp = PostExploitationInput(exploits=exploits)
    return await ai_post_exploitation(inp)


async def run_reporting(
    target: str,
    recon: ReconOutput | None,
    threat_model: ThreatModelOutput | None,
    vuln_analysis: VulnAnalysisOutput | None,
    exploitation: ExploitationOutput | None,
    post_exploitation: PostExploitationOutput | None,
) -> ReportingOutput:
    """Reporting: aggregates all real data and generates comprehensive report via LLM."""
    inp = ReportingInput(
        target=target,
        recon=recon,
        threat_model=threat_model,
        vuln_analysis=vuln_analysis,
        exploitation=exploitation,
        post_exploitation=post_exploitation,
    )
    return await ai_reporting(inp)
