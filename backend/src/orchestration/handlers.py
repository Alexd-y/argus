"""Phase handlers — production implementation with real tools and data sources."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import shlex
import socket
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle
from src.core.config import settings
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
from src.orchestration.raw_phase_artifacts import RawPhaseSink
from src.recon.vulnerability_analysis.active_scan.va_active_scan_phase import (
    run_va_active_scan_phase,
)
from src.recon.vulnerability_analysis.active_scan.web_vuln_heuristics import (
    run_web_vuln_heuristics,
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


_HTTP_CRAWL_TIMEOUT = 10.0
_HTTP_CRAWL_MAX_REDIRECTS = 3
_HTTP_CRAWL_USER_AGENT = "ARGUS-Scanner/1.0 (recon; +https://github.com/argus)"


class _FormHTMLParser(HTMLParser):
    """Lightweight stdlib parser that extracts <form> elements and their <input> fields."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current_form = {
                "action": attr_map.get("action", ""),
                "method": (attr_map.get("method", "GET")).upper(),
                "inputs": [],
            }
        elif tag == "input" and self._current_form is not None:
            input_name = attr_map.get("name", "")
            if input_name:
                self._current_form["inputs"].append({
                    "name": input_name,
                    "type": attr_map.get("type", "text"),
                    "value": attr_map.get("value", ""),
                })

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _extract_url_query_params(target: str) -> list[dict[str, Any]]:
    """Extract query parameters from a target URL string (no network call)."""
    parsed = urlparse(target)
    if not parsed.query:
        return []

    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}" if parsed.scheme else target.split("?")[0]
    params_inventory: list[dict[str, Any]] = []
    for param_name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        params_inventory.append({
            "url": base_url,
            "param": param_name,
            "value": values[0] if values else "",
            "method": "GET",
        })
    return params_inventory


def _parse_forms_from_html(html: str, page_url: str) -> list[dict[str, Any]]:
    """Parse HTML string and return forms_inventory rows (one per input)."""
    parser = _FormHTMLParser()
    try:
        parser.feed(html)
    except Exception:
        logger.debug("html_form_parse_error", extra={"page_url": page_url})
        return []

    forms_inventory: list[dict[str, Any]] = []
    for form in parser.forms:
        action_raw = form.get("action", "")
        action = urljoin(page_url, action_raw) if action_raw else page_url
        method = form.get("method", "GET")
        inputs: list[dict[str, Any]] = form.get("inputs", [])
        if not inputs:
            continue
        for inp in inputs:
            forms_inventory.append({
                "page_url": page_url,
                "action": action,
                "method": method,
                "input_name": inp["name"],
                "input_type": inp.get("type", "text"),
            })
    return forms_inventory


async def _extract_url_params_and_forms(
    target: str,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Extract URL query params (static) and HTML forms (via HTTP GET) for active scan targeting.

    Returns (params_inventory, forms_inventory). Both are safe to pass as empty lists on error.
    """
    params_inventory = _extract_url_query_params(target)

    forms_inventory: list[dict[str, Any]] = []

    parsed = urlparse(target)
    if not parsed.scheme or parsed.scheme not in ("http", "https"):
        logger.info("http_crawl_skipped", extra={"reason": "non_http_scheme"})
        return params_inventory, forms_inventory

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(_HTTP_CRAWL_TIMEOUT),
            max_redirects=_HTTP_CRAWL_MAX_REDIRECTS,
            follow_redirects=True,
            verify=False,
        ) as client:
            response = await client.get(
                target,
                headers={"User-Agent": _HTTP_CRAWL_USER_AGENT},
            )
        content_type = response.headers.get("content-type", "")
        if "html" not in content_type.lower():
            logger.info("http_crawl_no_html", extra={"content_type": content_type})
            return params_inventory, forms_inventory

        body = response.text[:500_000]
        forms_inventory = _parse_forms_from_html(body, str(response.url))

        page_params = _extract_url_query_params(str(response.url))
        existing_keys = {(p["url"], p["param"]) for p in params_inventory}
        for pp in page_params:
            if (pp["url"], pp["param"]) not in existing_keys:
                params_inventory.append(pp)

    except httpx.TooManyRedirects:
        logger.warning("http_crawl_too_many_redirects", extra={"target": target[:200]})
    except httpx.TimeoutException:
        logger.warning("http_crawl_timeout", extra={"target": target[:200]})
    except httpx.HTTPError as exc:
        logger.warning(
            "http_crawl_error",
            extra={"target": target[:200], "exc_type": type(exc).__name__},
        )
    except Exception:
        logger.warning("http_crawl_unexpected_error", extra={"target": target[:200]}, exc_info=True)

    logger.info(
        "http_crawl_complete",
        extra={
            "params_count": len(params_inventory),
            "forms_count": len(forms_inventory),
        },
    )
    return params_inventory, forms_inventory


async def _upload_recon_tool_streams(sink: RawPhaseSink, tool_results: dict[str, Any]) -> None:
    """Persist per-tool stdout/stderr as raw recon artifacts (best-effort)."""
    for name, result in tool_results.items():
        if not isinstance(result, dict):
            continue
        stdout = result.get("stdout")
        stderr = result.get("stderr")
        if isinstance(stdout, str) and stdout.strip():
            await asyncio.to_thread(sink.upload_text, f"tool_{name}_stdout", stdout)
        if isinstance(stderr, str) and stderr.strip():
            await asyncio.to_thread(sink.upload_text, f"tool_{name}_stderr", stderr)


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


def _log_recon_tool_done(tool: str, cmd: str, result: dict[str, Any]) -> None:
    """Log tool completion without target or full argv (argv count + exit metadata only)."""
    try:
        argv_count = len(shlex.split(cmd))
    except ValueError:
        argv_count = -1
    logger.info(
        "recon_tool_finished",
        extra={
            "tool": tool,
            "argv_count": argv_count,
            "return_code": result.get("return_code"),
            "success": result.get("success"),
        },
    )


async def _run_nmap(target: str, ports: str = "1-1000") -> dict[str, Any]:
    """Run nmap service/version scan. Tools installed in backend container."""
    cmd = f"nmap -sV -sC -T4 --open -p {ports} {target}"
    result = execute_command(cmd, use_sandbox=False)
    _log_recon_tool_done("nmap", cmd, result)
    return result


async def _run_dig(domain: str) -> dict[str, Any]:
    """Run dig for DNS records."""
    cmd = f"dig {domain} ANY +noall +answer"
    result = execute_command(cmd, use_sandbox=False)
    _log_recon_tool_done("dig", cmd, result)
    return result


async def _run_whois(domain: str) -> dict[str, Any]:
    """Run whois lookup."""
    cmd = f"whois {domain}"
    result = execute_command(cmd, use_sandbox=False)
    _log_recon_tool_done("whois", cmd, result)
    return result


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


async def run_recon(
    target: str,
    options: dict,
    *,
    tenant_id: str | None = None,
    scan_id: str | None = None,
) -> ReconOutput:
    """
    Production recon: nmap + dig + whois + crt.sh + Shodan -> LLM analysis.
    Runs tools in parallel, collects results, feeds to LLM for structured output.
    When tenant_id and scan_id are set, raw tool streams and LLM responses are uploaded to MinIO.
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
    ports = options.get("ports", "1-1000")

    nmap_task = _run_nmap(domain, ports)
    dig_task = _run_dig(domain)
    whois_task = _run_whois(domain)
    crtsh_task = _query_crtsh(domain)
    shodan_task = _query_shodan(domain)
    http_crawl_task = _extract_url_params_and_forms(target)

    results = await asyncio.gather(
        nmap_task, dig_task, whois_task, crtsh_task, shodan_task, http_crawl_task,
        return_exceptions=True,
    )

    http_crawl_result = results[-1]
    results = results[:-1]

    crawl_params: list[dict[str, Any]] = []
    crawl_forms: list[dict[str, Any]] = []
    if isinstance(http_crawl_result, tuple) and len(http_crawl_result) == 2:
        crawl_params, crawl_forms = http_crawl_result
    elif isinstance(http_crawl_result, Exception):
        logger.warning(
            "recon_http_crawl_failed",
            extra={"exc_type": type(http_crawl_result).__name__},
        )

    tool_results: dict[str, Any] = {}
    tool_names = ["nmap", "dig", "whois", "crtsh", "shodan"]
    for name, result in zip(tool_names, results, strict=True):
        if isinstance(result, Exception):
            exc = result
            errno = getattr(exc, "errno", None)
            logger.warning(
                "recon_tool_failed",
                extra={
                    "tool": name,
                    "exc_type": type(exc).__name__,
                    "errno": errno,
                },
            )
            tool_results[name] = {"success": False, "stdout": "", "stderr": str(result)}
        else:
            tool_results[name] = result

    if crawl_params or crawl_forms:
        tool_results["http_crawl"] = {
            "success": True,
            "stdout": _safe_json(
                {"params_inventory": crawl_params, "forms_inventory": crawl_forms},
                15000,
            ),
        }

    tool_results_str = _format_tool_results(tool_results)
    logger.info("Recon tool results collected (%d chars), sending to LLM", len(tool_results_str))

    raw_sink: RawPhaseSink | None = None
    if tenant_id and scan_id:
        raw_sink = RawPhaseSink(tenant_id, scan_id, "recon")
        await _upload_recon_tool_streams(raw_sink, tool_results)
        await asyncio.to_thread(raw_sink.upload_text, "tool_results_llm_context", tool_results_str)

    inp = ReconInput(target=target, options=options)
    return await ai_recon(inp, tool_results=tool_results_str, raw_sink=raw_sink)


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


# CVSS v3.1 defaults / floors for confirmed vulnerabilities by type.
_CVSS_DEFAULTS: dict[str, float] = {
    "xss": 7.2,
    "sqli": 9.8,
    "sql_injection": 9.8,
    "rce": 9.8,
    "ssrf": 8.6,
    "lfi": 8.6,
    "rfi": 9.0,
    "open_redirect": 4.7,
}
_MIN_CONFIRMED_XSS_CVSS = 7.0
_MIN_CONFIRMED_ACTIVE_CVSS = 7.0

_CWE_MAP: dict[str, str] = {
    "xss": "CWE-79",
    "sqli": "CWE-89",
    "sql_injection": "CWE-89",
    "rce": "CWE-78",
    "ssrf": "CWE-918",
    "lfi": "CWE-22",
    "rfi": "CWE-98",
    "open_redirect": "CWE-601",
    "csrf": "CWE-352",
    "idor": "CWE-639",
}


def _generate_poc(finding_data: dict[str, Any]) -> str:
    """Generate a safe PoC curl command or URL string from finding data."""
    poc = str(finding_data.get("poc") or "").strip()
    url = str(finding_data.get("url") or "").strip()
    param = str(finding_data.get("param") or "").strip()
    target = poc or url
    if not target:
        return ""
    safe_target = target.replace("'", "'\\''")
    cmd = f"curl -v '{safe_target}'"
    if param:
        cmd += f"  # parameter: {param}"
    return cmd


def _normalize_intel_finding(raw: dict[str, Any]) -> dict[str, Any]:
    """Normalize an active-scan intel_finding dict to the standard findings format."""
    data = raw.get("data") or {}
    vuln_type = data.get("type") or data.get("template_id") or "unknown"
    vuln_type_lower = str(vuln_type).lower().strip()
    title = data.get("name") or f"{vuln_type} finding"
    if data.get("url"):
        title = f"{title} — {data['url']}"
    severity = (data.get("severity") or "info").lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        severity = "info"

    cvss: float | None = None
    raw_cvss = data.get("cvss_score") or data.get("cvss")
    if isinstance(raw_cvss, (int, float)):
        cvss = float(raw_cvss)

    is_xss = vuln_type_lower in ("xss", "cross-site scripting", "reflected_xss", "stored_xss")
    if is_xss:
        default_cvss = _CVSS_DEFAULTS.get("xss", 7.2)
        cvss = max(cvss or 0.0, default_cvss)
        if cvss < _MIN_CONFIRMED_XSS_CVSS:
            cvss = _MIN_CONFIRMED_XSS_CVSS
    elif cvss is None and vuln_type_lower in _CVSS_DEFAULTS:
        cvss = _CVSS_DEFAULTS[vuln_type_lower]

    cwe = data.get("cwe") or data.get("cwe_id") or ""
    if not cwe and is_xss:
        cwe = "CWE-79"
    elif not cwe:
        cwe = _CWE_MAP.get(vuln_type_lower, "")

    poc_cmd = _generate_poc(data)

    description_parts = [data.get("type", "")]
    if data.get("param"):
        description_parts.append(f"Parameter: {data['param']}")
    if data.get("poc"):
        description_parts.append(f"Payload: {data['poc']}")
    if poc_cmd:
        description_parts.append(f"PoC: {poc_cmd}")
    if data.get("matched_at"):
        description_parts.append(f"Matched: {data['matched_at']}")
    description = "; ".join(p for p in description_parts if p)
    return {
        "title": title[:500],
        "severity": severity,
        "description": description[:5000],
        "cwe": str(cwe)[:20] if cwe else None,
        "cvss": cvss,
        "source": "active_scan",
    }


def _build_active_scan_context(findings: list[dict[str, Any]]) -> str:
    """Build a prompt-safe context string from active scan findings for LLM consumption."""
    if not findings:
        return ""
    lines = ["Active scan findings (from automated security tools):\n"]
    for i, f in enumerate(findings[:50], 1):
        parts = [f"  {i}. [{f.get('severity', 'info').upper()}] {f.get('title', 'N/A')}"]
        if f.get("cwe"):
            parts.append(f"CWE: {f['cwe']}")
        if f.get("cvss") is not None:
            parts.append(f"CVSS: {f['cvss']}")
        if f.get("description"):
            parts.append(f"Details: {f['description'][:300]}")
        lines.append(" | ".join(parts))
    lines.append("")
    return "\n".join(lines) + "\n"


def _postprocess_findings_cvss(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Post-process LLM + active-scan findings: assign default CVSS, enforce floors, sort desc."""
    for f in findings:
        title_lower = (f.get("title") or "").lower()
        desc_lower = (f.get("description") or "").lower()
        severity = (f.get("severity") or "").lower()
        cvss = f.get("cvss")

        is_xss = any(kw in title_lower or kw in desc_lower for kw in ("xss", "cross-site scripting"))
        is_sqli = any(kw in title_lower or kw in desc_lower for kw in ("sqli", "sql injection"))

        if is_xss:
            if not f.get("cwe"):
                f["cwe"] = "CWE-79"
            if cvss is None or cvss < _MIN_CONFIRMED_XSS_CVSS:
                f["cvss"] = _CVSS_DEFAULTS.get("xss", 7.2)
        elif is_sqli:
            if not f.get("cwe"):
                f["cwe"] = "CWE-89"
            if cvss is None:
                f["cvss"] = _CVSS_DEFAULTS.get("sqli", 9.8)
        elif f.get("source") == "active_scan" and severity in ("critical", "high"):
            if cvss is None or cvss < _MIN_CONFIRMED_ACTIVE_CVSS:
                f["cvss"] = _MIN_CONFIRMED_ACTIVE_CVSS

    findings.sort(key=lambda f: f.get("cvss") or 0.0, reverse=True)
    return findings


async def run_vuln_analysis(
    threat_model: dict,
    assets: list[str],
    *,
    target: str = "",
    tenant_id: str | None = None,
    scan_id: str | None = None,
) -> VulnAnalysisOutput:
    """Production vuln analysis: optional active scan + LLM analysis.

    When sandbox is enabled and a target is provided, the VA active-scan pipeline
    (dalfox, nuclei, ffuf, etc.) runs first. Its findings are fed into the LLM
    prompt as additional context and merged into the final output.
    Falls back to LLM-only when sandbox is disabled or active scan fails.
    """
    active_scan_findings: list[dict[str, Any]] = []
    active_scan_context = ""
    params_inv: list[dict[str, Any]] = []
    forms_inv: list[dict[str, Any]] = []

    if settings.sandbox_enabled and target:
        try:
            params_inv, forms_inv = await _extract_url_params_and_forms(target)
            bundle = VulnerabilityAnalysisInputBundle(
                engagement_id=scan_id or "unknown",
                target_id=target[:36],
                entry_points=[],
                threat_scenarios=[],
                params_inventory=params_inv,
                forms_inventory=forms_inv,
                intel_findings=[],
                live_hosts=[{"host": target}],
                tech_profile=[],
            )
            result_bundle = await run_va_active_scan_phase(
                bundle,
                tenant_id_raw=tenant_id,
                scan_id_raw=scan_id or "",
                va_raw_log=lambda msg: logger.info(
                    "va_active_scan",
                    extra={"message": msg, "scan_id": scan_id},
                ),
            )
            raw_intel = result_bundle.intel_findings or []
            active_scan_findings = [_normalize_intel_finding(f) for f in raw_intel]
            active_scan_context = _build_active_scan_context(active_scan_findings)

            if tenant_id and scan_id and active_scan_findings:
                raw_sink = RawPhaseSink(tenant_id, scan_id, "vuln_analysis")
                await asyncio.to_thread(
                    raw_sink.upload_json,
                    "active_scan_findings",
                    {"findings": active_scan_findings, "count": len(active_scan_findings)},
                )

            logger.info(
                "va_active_scan_complete",
                extra={
                    "scan_id": scan_id,
                    "findings_count": len(active_scan_findings),
                },
            )

        except Exception:
            logger.warning(
                "va_active_scan_failed_fallback_to_llm",
                extra={"scan_id": scan_id},
                exc_info=True,
            )

    if target:
        try:
            if not params_inv and not forms_inv:
                params_inv, forms_inv = await _extract_url_params_and_forms(target)
            heuristic_findings = await run_web_vuln_heuristics(
                target, params_inv, forms_inv,
            )
            if heuristic_findings:
                heuristic_normalized = [
                    _normalize_intel_finding(f) for f in heuristic_findings
                ]
                active_scan_findings.extend(heuristic_normalized)
                active_scan_context = _build_active_scan_context(active_scan_findings)
                logger.info(
                    "web_vuln_heuristics_merged",
                    extra={
                        "scan_id": scan_id,
                        "heuristic_count": len(heuristic_normalized),
                    },
                )
        except Exception:
            logger.warning(
                "web_vuln_heuristics_failed",
                extra={"scan_id": scan_id},
                exc_info=True,
            )

    inp = VulnAnalysisInput(threat_model=threat_model, assets=assets)
    llm_output = await ai_vuln_analysis(inp, active_scan_context=active_scan_context)

    if active_scan_findings:
        seen_titles = {f.get("title", "").lower() for f in llm_output.findings}
        for asf in active_scan_findings:
            if asf.get("title", "").lower() not in seen_titles:
                llm_output.findings.append(asf)
                seen_titles.add(asf.get("title", "").lower())

    llm_output.findings = _postprocess_findings_cvss(llm_output.findings)
    return llm_output


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
    *,
    tenant_id: str | None = None,
    scan_id: str | None = None,
) -> PostExploitationOutput:
    """Post exploitation: LLM analyzes lateral movement and persistence."""
    raw_sink: RawPhaseSink | None = None
    if tenant_id and scan_id:
        raw_sink = RawPhaseSink(tenant_id, scan_id, "post_exploitation")
    inp = PostExploitationInput(exploits=exploits)
    return await ai_post_exploitation(inp, raw_sink=raw_sink)


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
