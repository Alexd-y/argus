"""Perplexity-powered CVE and OSINT enrichment using web search LLM."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CVEIntel:
    cve_id: str
    cvss_v3: float | None = None
    severity: str | None = None
    description: str = ""
    exploit_available: bool = False
    exploit_sources: list[str] = field(default_factory=list)
    patch_available: bool = False
    patch_url: str | None = None
    actively_exploited: bool = False
    affected_versions: list[str] = field(default_factory=list)
    remediation: str = ""


@dataclass
class DomainOSINT:
    domain: str
    breaches: list[dict[str, str]] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    subdomains: list[str] = field(default_factory=list)
    public_vulns: list[str] = field(default_factory=list)
    org_info: dict[str, str] = field(default_factory=dict)


def _perplexity_enabled() -> bool:
    return bool(
        os.environ.get("PERPLEXITY_API_KEY", "").strip()
        and os.environ.get("PERPLEXITY_INTEL_ENABLED", "true").lower() == "true"
    )


_CVE_ENRICH_SYSTEM = (
    "You are a vulnerability intelligence analyst. "
    "Search for current information about the given CVE and respond in JSON only. "
    "Do not include markdown formatting. Return only a valid JSON object."
)

_CVE_ENRICH_USER = (
    "Research CVE {cve_id} affecting {product}.\n"
    "Return JSON with these exact keys:\n"
    '{{\n'
    '  "cvss_v3": <float or null>,\n'
    '  "severity": "<critical/high/medium/low>",\n'
    '  "description": "<one sentence>",\n'
    '  "exploit_available": <true/false>,\n'
    '  "exploit_sources": ["<url>"],\n'
    '  "patch_available": <true/false>,\n'
    '  "patch_url": "<url or null>",\n'
    '  "actively_exploited": <true/false>,\n'
    '  "affected_versions": ["<version range>"],\n'
    '  "remediation": "<one sentence action>"\n'
    '}}'
)

_OSINT_SYSTEM = (
    "You are an OSINT analyst. Search for public information only. "
    "Do not include private or sensitive data. Respond in JSON only. "
    "Do not include markdown formatting."
)

_OSINT_USER = (
    "Research this domain for a security assessment: {domain}\n"
    "Find:\n"
    "1. Known data breaches or leaks (cite sources)\n"
    "2. Technology stack (from public job listings, cert transparency, etc.)\n"
    "3. Related subdomains or infrastructure\n"
    "4. Any public security disclosures or bug bounty reports\n"
    "5. Company/org background relevant to attack surface\n\n"
    "Return JSON with these exact keys:\n"
    '{{\n'
    '  "breaches": [{{"source": "<str>", "date": "<str>", "description": "<str>"}}],\n'
    '  "tech_stack": ["<technology>"],\n'
    '  "subdomains": ["<subdomain>"],\n'
    '  "public_vulns": ["<description>"],\n'
    '  "org_info": {{"industry": "<str>", "size": "<str>", "notes": "<str>"}}\n'
    '}}'
)


async def enrich_cve(cve_id: str, product: str = "") -> CVEIntel | None:
    """Search for CVE intelligence using Perplexity web search."""
    if not _perplexity_enabled():
        return None

    from src.llm.task_router import LLMTask, call_llm_for_task

    try:
        response = await call_llm_for_task(
            LLMTask.PERPLEXITY_OSINT,
            _CVE_ENRICH_USER.format(cve_id=cve_id, product=product or "unknown"),
            system_prompt=_CVE_ENRICH_SYSTEM,
        )
        data = _parse_json_response(response.text)
        if not data:
            return None
        return CVEIntel(
            cve_id=cve_id,
            cvss_v3=_safe_float(data.get("cvss_v3")),
            severity=data.get("severity"),
            description=str(data.get("description", ""))[:500],
            exploit_available=bool(data.get("exploit_available")),
            exploit_sources=data.get("exploit_sources", []) or [],
            patch_available=bool(data.get("patch_available")),
            patch_url=data.get("patch_url"),
            actively_exploited=bool(data.get("actively_exploited")),
            affected_versions=data.get("affected_versions", []) or [],
            remediation=str(data.get("remediation", ""))[:500],
        )
    except Exception:
        logger.warning(
            "Perplexity CVE enrichment failed",
            extra={
                "event": "argus.perplexity_cve_failed",
                "cve_id": cve_id,
            },
            exc_info=True,
        )
        return None


async def osint_domain(domain: str) -> DomainOSINT | None:
    """OSINT lookup for target domain via Perplexity web search."""
    if not _perplexity_enabled():
        return None

    from src.llm.task_router import LLMTask, call_llm_for_task

    try:
        response = await call_llm_for_task(
            LLMTask.PERPLEXITY_OSINT,
            _OSINT_USER.format(domain=domain),
            system_prompt=_OSINT_SYSTEM,
        )
        data = _parse_json_response(response.text)
        if not data:
            return None
        return DomainOSINT(
            domain=domain,
            breaches=data.get("breaches", []) or [],
            tech_stack=data.get("tech_stack", []) or [],
            subdomains=data.get("subdomains", []) or [],
            public_vulns=data.get("public_vulns", []) or [],
            org_info=data.get("org_info", {}) or {},
        )
    except Exception:
        logger.warning(
            "Perplexity OSINT domain lookup failed",
            extra={
                "event": "argus.perplexity_osint_failed",
                "domain": domain,
            },
            exc_info=True,
        )
        return None


async def enrich_findings_with_cve_intel(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Enrich findings that have CVE IDs with Perplexity intelligence.

    Sets exploit_public=True and exploit_sources on findings where
    a public exploit is known. Also annotates actively exploited CVEs,
    patch URLs, and remediation guidance.
    """
    if not _perplexity_enabled():
        return findings

    for finding in findings:
        cve_ids = finding.get("cve_ids") or []
        if not isinstance(cve_ids, list) or not cve_ids:
            continue

        primary_cve = cve_ids[0]
        product = finding.get("affected_asset") or finding.get("title") or ""
        intel = await enrich_cve(primary_cve, product=product)
        if not intel:
            continue

        if intel.exploit_available:
            finding["exploit_public"] = True
            finding["exploit_sources"] = intel.exploit_sources
        if intel.actively_exploited:
            finding["actively_exploited"] = True
        if intel.patch_url:
            finding["patch_url"] = intel.patch_url
        if intel.remediation:
            finding["perplexity_remediation"] = intel.remediation

    return findings


def _parse_json_response(text: str) -> dict[str, Any] | None:
    """Parse JSON from LLM response, stripping markdown fences if present."""
    if not text:
        return None
    cleaned = text.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        start = 1
        end = len(lines)
        for i, line in enumerate(lines):
            if i > 0 and line.strip().startswith("```"):
                end = i
                break
        cleaned = "\n".join(lines[start:end]).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        logger.warning(
            "Failed to parse Perplexity JSON response",
            extra={"event": "argus.perplexity_json_parse_failed"},
        )
        return None


def _safe_float(val: Any) -> float | None:
    if val is None:
        return None
    try:
        return float(val)
    except (ValueError, TypeError):
        return None
