"""Intelligence API — target analysis, CVE/OSINT, Shodan (HexStrike v4 alignment)."""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
from typing import Any

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

from src.api.schemas import (
    IntelligenceAnalyzeTargetRequest,
    IntelligenceCveIntelBody,
    IntelligenceCveRequest,
    IntelligenceOsintDomainRequest,
    IntelligenceShodanServiceItem,
    IntelligenceShodanSummary,
)
from src.intel.shodan_enricher import ShodanResult, enrich_target_host
from src.llm.errors import LLMAllProvidersFailedError, LLMProviderUnavailableError
from src.llm.router import call_llm, is_llm_available

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/intelligence", tags=["intelligence"])

_ANALYZE_SYSTEM = (
    "You are an expert penetration tester. Respond with a single valid JSON object only. "
    "No markdown fences or commentary."
)

_ANALYZE_USER_TEMPLATE = """
You are analyzing a target for an authorized security assessment.
Target: {target}
Analysis type: {analysis_type}

Instructions for analysis type:
- comprehensive: full attack surface, stack, vuln mapping, tool list, time estimate.
- quick: prioritize highest-risk items and fewer tools.
- passive: only OSINT-safe, non-intrusive observations.

Perform:
1. Identify attack surface (subdomains, IPs, ports, web services) as an array of strings or objects.
2. Detect technology stack as a JSON object (frameworks, CMS, DB, CDN).
3. Map potential vulnerability categories as an array of strings.
4. Recommend tools as an array of strings.
5. testing_priority: exactly one of high, medium, low.
6. estimated_time_minutes: integer minutes for a reasonable engagement scope.

Output JSON with exactly these keys:
{{
  "attack_surface": [],
  "tech_stack": {{}},
  "vuln_categories": [],
  "recommended_tools": [],
  "testing_priority": "high|medium|low",
  "estimated_time_minutes": 0
}}
"""


def _failure_json(status_code: int, detail: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"success": False, "detail": detail},
    )


def _parse_json_from_llm(text: str) -> dict[str, Any] | None:
    if not text or not text.strip():
        return None
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        start, end = 1, len(lines)
        for i, line in enumerate(lines):
            if i > 0 and line.strip().startswith("```"):
                end = i
                break
        cleaned = "\n".join(lines[start:end]).strip()
    try:
        parsed = json.loads(cleaned)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        logger.warning(
            "Intelligence LLM JSON parse failed",
            extra={"event": "argus.intelligence.json_parse_failed"},
        )
        return None


def _normalize_analyze_payload(raw: dict[str, Any]) -> dict[str, Any]:
    def _list(key: str) -> list[Any]:
        v = raw.get(key)
        return v if isinstance(v, list) else []

    def _dict_key(key: str) -> dict[str, Any]:
        v = raw.get(key)
        return v if isinstance(v, dict) else {}

    tp = raw.get("testing_priority")
    if tp not in ("high", "medium", "low"):
        tp = "medium"

    etm_raw = raw.get("estimated_time_minutes", 60)
    try:
        etm = int(etm_raw)
        etm = max(1, min(10080, etm))
    except (TypeError, ValueError):
        etm = 60

    return {
        "success": True,
        "attack_surface": _list("attack_surface"),
        "tech_stack": _dict_key("tech_stack"),
        "vuln_categories": _list("vuln_categories"),
        "recommended_tools": _list("recommended_tools"),
        "testing_priority": tp,
        "estimated_time_minutes": etm,
    }


def _normalize_domain_host(raw: str) -> str:
    s = raw.strip().lower()
    if s.startswith("https://"):
        s = s[8:]
    elif s.startswith("http://"):
        s = s[7:]
    s = s.split("/")[0].split("?")[0]
    if ":" in s and not s.startswith("["):
        host, _, port = s.rpartition(":")
        if port.isdigit():
            s = host
    return s.strip(".") or s


_DOMAIN_LABEL = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


def _is_plausible_domain(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if host.startswith("[") and host.endswith("]"):
        return False
    return bool(_DOMAIN_LABEL.match(host))


async def _resolve_ipv4_for_host(host: str) -> str | None:
    import asyncio

    def _lookup() -> str | None:
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
            for _fam, _t, _p, _c, sockaddr in infos:
                return sockaddr[0]
        except OSError:
            return None
        return None

    try:
        ipaddress.IPv4Address(host)
        return host
    except ipaddress.AddressValueError:
        pass

    return await asyncio.to_thread(_lookup)


def _shodan_to_summary(result: ShodanResult) -> dict[str, Any]:
    svc_models = [
        IntelligenceShodanServiceItem(
            port=s.port,
            transport=s.transport,
            product=s.product,
            version=s.version,
            cpe=list(s.cpe or []),
        )
        for s in result.services
    ]
    summary = IntelligenceShodanSummary(
        ip=result.ip,
        hostnames=list(result.hostnames or []),
        org=result.org,
        country=result.country,
        open_ports=list(result.open_ports or []),
        vulns=list(result.vulns or []),
        services=svc_models,
    )
    return summary.model_dump()


@router.post("/analyze-target")
async def analyze_target(body: IntelligenceAnalyzeTargetRequest) -> JSONResponse:
    if not is_llm_available():
        logger.info(
            "Analyze-target rejected: no LLM provider",
            extra={
                "event": "argus.intelligence.analyze_no_llm",
                "operator_hint": (
                    "configure at least one LLM provider env (OPENAI_API_KEY, "
                    "DEEPSEEK_API_KEY, OPENROUTER_API_KEY, etc.)"
                ),
            },
        )
        return _failure_json(503, "LLM service is not configured.")

    prompt = _ANALYZE_USER_TEMPLATE.format(
        target=body.target.strip(),
        analysis_type=body.analysis_type,
    )
    try:
        text = await call_llm(prompt, system_prompt=_ANALYZE_SYSTEM)
    except (LLMProviderUnavailableError, LLMAllProvidersFailedError) as exc:
        logger.warning(
            "Analyze-target LLM call failed",
            extra={
                "event": "argus.intelligence.analyze_llm_failed",
                "error_type": type(exc).__name__,
            },
        )
        return _failure_json(503, "LLM analysis is temporarily unavailable.")
    except Exception as exc:
        logger.warning(
            "Analyze-target unexpected failure",
            extra={
                "event": "argus.intelligence.analyze_unexpected",
                "error_type": type(exc).__name__,
            },
            exc_info=True,
        )
        return _failure_json(503, "LLM analysis is temporarily unavailable.")

    try:
        data = _parse_json_from_llm(text)
        if not data:
            return _failure_json(503, "LLM returned an invalid response; try again later.")
        return JSONResponse(status_code=200, content=_normalize_analyze_payload(data))
    except Exception as exc:
        logger.warning(
            "Analyze-target post-LLM handling failed",
            extra={
                "event": "argus.intelligence.analyze_post_llm_failed",
                "error_type": type(exc).__name__,
            },
            exc_info=True,
        )
        return _failure_json(503, "LLM returned an invalid response; try again later.")


@router.post("/cve")
async def intelligence_cve(body: IntelligenceCveRequest) -> JSONResponse:
    from src.intel.perplexity_enricher import enrich_cve

    intel = await enrich_cve(body.cve_id.strip().upper(), product=(body.product or "") or "")
    if intel is None:
        logger.info(
            "CVE intelligence unavailable",
            extra={
                "event": "argus.intelligence.cve_unavailable",
                "cve_id": body.cve_id,
                "operator_hint": "PERPLEXITY_API_KEY and PERPLEXITY_INTEL_ENABLED",
            },
        )
        return _failure_json(503, "Threat intelligence service is temporarily unavailable.")

    payload = IntelligenceCveIntelBody(
        cve_id=intel.cve_id,
        cvss_v3=intel.cvss_v3,
        severity=intel.severity,
        description=intel.description,
        exploit_available=intel.exploit_available,
        exploit_sources=list(intel.exploit_sources or []),
        patch_available=intel.patch_available,
        patch_url=intel.patch_url,
        actively_exploited=intel.actively_exploited,
        affected_versions=list(intel.affected_versions or []),
        remediation=intel.remediation,
    )
    return JSONResponse(status_code=200, content={"success": True, **payload.model_dump()})


@router.post("/osint-domain")
async def osint_domain(body: IntelligenceOsintDomainRequest) -> JSONResponse:
    from src.intel.perplexity_enricher import osint_domain as perplexity_osint

    host = _normalize_domain_host(body.domain)
    if not _is_plausible_domain(host):
        return _failure_json(400, "Invalid domain hostname.")

    osint = await perplexity_osint(host)
    if osint is None:
        logger.info(
            "OSINT domain unavailable",
            extra={
                "event": "argus.intelligence.osint_unavailable",
                "domain": host,
                "operator_hint": "PERPLEXITY_API_KEY and PERPLEXITY_INTEL_ENABLED",
            },
        )
        return _failure_json(503, "Threat intelligence service is temporarily unavailable.")

    shodan_summary: dict[str, Any] | None = None
    ip = await _resolve_ipv4_for_host(host)
    if ip:
        try:
            shodan_result = await enrich_target_host(ip)
            if shodan_result is not None:
                shodan_summary = _shodan_to_summary(shodan_result)
        except Exception as exc:
            logger.warning(
                "OSINT Shodan combine failed",
                extra={
                    "event": "argus.intelligence.osint_shodan_failed",
                    "error_type": type(exc).__name__,
                },
                exc_info=True,
            )

    content: dict[str, Any] = {
        "success": True,
        "domain": osint.domain,
        "breaches": osint.breaches,
        "tech_stack": osint.tech_stack,
        "subdomains": osint.subdomains,
        "public_vulns": osint.public_vulns,
        "org_info": osint.org_info,
        "shodan": shodan_summary,
    }
    return JSONResponse(status_code=200, content=content)


@router.get("/shodan")
async def intelligence_shodan(ip: str = Query(..., min_length=2, max_length=64)) -> JSONResponse:
    ip = ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return _failure_json(400, "Invalid IP address.")

    try:
        result = await enrich_target_host(ip)
    except Exception:
        logger.warning(
            "Shodan intelligence endpoint failed",
            extra={"event": "argus.intelligence.shodan_endpoint_failed", "ip": ip},
            exc_info=True,
        )
        return _failure_json(503, "Shodan lookup failed.")

    if result is None:
        logger.info(
            "Shodan intelligence unavailable or no data",
            extra={
                "event": "argus.intelligence.shodan_no_data",
                "ip": ip,
                "operator_hint": (
                    "SHODAN_API_KEY, SHODAN_ENRICHMENT_ENABLED, or no Shodan record for host"
                ),
            },
        )
        return _failure_json(503, "Threat intelligence service is temporarily unavailable.")

    return JSONResponse(
        status_code=200,
        content={"success": True, "host": _shodan_to_summary(result)},
    )
