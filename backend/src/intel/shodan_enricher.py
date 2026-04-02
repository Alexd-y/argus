"""Shodan enrichment — cross-reference findings with Shodan host intelligence."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ShodanService:
    port: int
    transport: str = "tcp"
    product: str | None = None
    version: str | None = None
    cpe: list[str] = field(default_factory=list)
    banner: str = ""


@dataclass
class ShodanResult:
    ip: str | None = None
    hostnames: list[str] = field(default_factory=list)
    org: str | None = None
    isp: str | None = None
    asn: str | None = None
    country: str | None = None
    open_ports: list[int] = field(default_factory=list)
    services: list[ShodanService] = field(default_factory=list)
    vulns: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def _shodan_enabled() -> bool:
    return bool(
        os.environ.get("SHODAN_API_KEY", "").strip()
        and os.environ.get("SHODAN_ENRICHMENT_ENABLED", "true").lower() == "true"
    )


async def enrich_target_host(target_ip: str) -> ShodanResult | None:
    """Query Shodan for target host. Returns None if unavailable or error.

    Uses synchronous shodan SDK in thread pool to avoid blocking event loop.
    """
    if not _shodan_enabled():
        return None

    import asyncio

    def _query() -> ShodanResult | None:
        try:
            import shodan
        except ImportError:
            logger.warning("shodan package not installed, skipping enrichment")
            return None

        api_key = os.environ.get("SHODAN_API_KEY", "").strip()
        if not api_key:
            return None

        api = shodan.Shodan(api_key)
        try:
            host = api.host(target_ip)
        except shodan.APIError as exc:
            logger.warning(
                "Shodan lookup failed",
                extra={
                    "event": "argus.shodan_lookup_failed",
                    "target": target_ip,
                    "error": str(exc),
                },
            )
            return None

        services = []
        for item in host.get("data", []):
            services.append(
                ShodanService(
                    port=item.get("port", 0),
                    transport=item.get("transport", "tcp"),
                    product=item.get("product"),
                    version=item.get("version"),
                    cpe=item.get("cpe", []) or [],
                    banner=(item.get("data", "") or "")[:500],
                )
            )

        return ShodanResult(
            ip=host.get("ip_str"),
            hostnames=host.get("hostnames", []) or [],
            org=host.get("org"),
            isp=host.get("isp"),
            asn=host.get("asn"),
            country=host.get("country_name"),
            open_ports=[s.port for s in services],
            services=services,
            vulns=list((host.get("vulns") or {}).keys()),
            tags=host.get("tags", []) or [],
        )

    return await asyncio.to_thread(_query)


def cross_reference_findings(
    shodan_result: ShodanResult | None,
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Cross-reference findings with Shodan CVEs and service data.

    Mutations:
    - Sets shodan_confirmed=True when Shodan CVEs match finding CVEs
    - Sets shodan_cves list of matched CVEs
    - Upgrades confidence to "confirmed" on match
    - Adds shodan_service_info for port-matched findings
    """
    if not shodan_result or not shodan_result.vulns:
        return findings

    shodan_cve_set = set(shodan_result.vulns)

    for finding in findings:
        cve_ids = finding.get("cve_ids") or []
        if not isinstance(cve_ids, list):
            cve_ids = [cve_ids] if isinstance(cve_ids, str) else []

        if cve_ids:
            matched = set(cve_ids) & shodan_cve_set
            if matched:
                finding["shodan_confirmed"] = True
                finding["shodan_cves"] = sorted(matched)
                finding["confidence"] = "confirmed"

        affected_port = finding.get("affected_port")
        if isinstance(affected_port, int):
            for svc in shodan_result.services:
                if svc.port == affected_port and svc.product:
                    finding["shodan_service_info"] = (
                        f"{svc.product} {svc.version or ''}".strip()
                    )
                    break

    return findings


def create_findings_from_shodan_vulns(
    shodan_result: ShodanResult,
    existing_cves: set[str] | None = None,
) -> list[dict[str, Any]]:
    """Create new findings from Shodan-reported CVEs not already in scan findings."""
    if not shodan_result or not shodan_result.vulns:
        return []

    skip = existing_cves or set()
    new_findings: list[dict[str, Any]] = []

    for cve_id in shodan_result.vulns:
        if cve_id in skip:
            continue
        new_findings.append(
            {
                "severity": "high",
                "title": f"Shodan-reported vulnerability: {cve_id}",
                "description": (
                    f"Shodan reports {cve_id} affecting host "
                    f"{shodan_result.ip or 'unknown'}. "
                    f"Organization: {shodan_result.org or 'N/A'}. "
                    "This CVE was detected by Shodan's passive scanning "
                    "infrastructure."
                ),
                "cwe": None,
                "cvss": None,
                "cve_ids": [cve_id],
                "confidence": "confirmed",
                "evidence_type": "shodan_passive",
                "evidence_refs": [f"shodan:{shodan_result.ip}"],
                "shodan_confirmed": True,
                "shodan_cves": [cve_id],
            }
        )

    return new_findings


def shodan_tech_stack_for_report(
    shodan_result: ShodanResult | None,
) -> dict[str, Any]:
    """Extract Shodan data for Valhalla tech stack section."""
    if not shodan_result:
        return {}
    return {
        "shodan_ip": shodan_result.ip,
        "shodan_org": shodan_result.org,
        "shodan_isp": shodan_result.isp,
        "shodan_asn": shodan_result.asn,
        "shodan_country": shodan_result.country,
        "shodan_open_ports": shodan_result.open_ports,
        "shodan_services": [
            {
                "port": s.port,
                "product": s.product,
                "version": s.version,
                "transport": s.transport,
            }
            for s in shodan_result.services[:20]
        ],
        "shodan_vulns_count": len(shodan_result.vulns),
        "shodan_tags": shodan_result.tags,
    }
