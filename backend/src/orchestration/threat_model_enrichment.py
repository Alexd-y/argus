"""ARGUS-009 — Threat model enrichment: structured recon context → STRIDE-based threat model.

Extracts technologies, ports, endpoints, forms, and entry points from recon
results and asset strings to feed the threat modeling LLM with actionable data.
"""

from __future__ import annotations

import logging
import re
from dataclasses import asdict, dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_VERSION_RE = re.compile(
    r"(?P<name>[A-Za-z][A-Za-z0-9_.+-]*)"
    r"[/\s]+"
    r"(?P<version>\d+(?:\.\d+){0,4}(?:[a-zA-Z0-9._-]*)?)",
)
_PORT_SERVICE_RE = re.compile(
    r"(?P<port>\d{1,5})/(?P<proto>tcp|udp)\s+(?:open\s+)?(?P<service>\S+)"
    r"(?:\s+(?P<detail>.+))?",
    re.IGNORECASE,
)
_ENDPOINT_PATTERNS = re.compile(
    r"(?:^|\s|,)(\/[a-zA-Z0-9_./-]{1,256})", re.MULTILINE
)

_FORM_TYPE_KEYWORDS: dict[str, str] = {
    "login": "authentication",
    "signin": "authentication",
    "register": "registration",
    "signup": "registration",
    "search": "search",
    "contact": "contact",
    "upload": "file_upload",
    "comment": "user_input",
    "password": "authentication",
    "reset": "password_reset",
}


@dataclass
class AttackSurfaceItem:
    component: str
    type: str  # web_form, api_endpoint, file_upload, admin_panel, service
    exposure_level: str  # external, internal, authenticated
    url: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class StrideThreat:
    category: str  # S, T, R, I, D, E
    description: str
    component: str
    likelihood: str  # high, medium, low
    impact: str  # high, medium, low

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class CveReference:
    cve_id: str
    technology: str
    severity: str
    description: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass
class ThreatModelResult:
    attack_surface: list[AttackSurfaceItem] = field(default_factory=list)
    threats: list[StrideThreat] = field(default_factory=list)
    cves: list[CveReference] = field(default_factory=list)
    mitigations: list[dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_surface": [i.to_dict() for i in self.attack_surface],
            "threats": [t.to_dict() for t in self.threats],
            "cves": [c.to_dict() for c in self.cves],
            "mitigations": self.mitigations,
        }


def _classify_form(action: str, inputs: list[dict[str, Any]]) -> str:
    """Classify an HTML form by its action URL and input fields."""
    blob = action.lower()
    for inp in inputs:
        blob += " " + (inp.get("input_name") or inp.get("name") or "").lower()
        blob += " " + (inp.get("input_type") or inp.get("type") or "").lower()

    for keyword, form_type in _FORM_TYPE_KEYWORDS.items():
        if keyword in blob:
            return form_type
    if any(
        (inp.get("input_type") or inp.get("type") or "").lower() == "file"
        for inp in inputs
    ):
        return "file_upload"
    return "general"


def extract_technologies_from_assets(assets: list[str]) -> list[dict[str, str]]:
    """Extract technology name+version pairs from asset description strings."""
    seen: set[str] = set()
    technologies: list[dict[str, str]] = []
    for asset in assets:
        for match in _VERSION_RE.finditer(asset):
            name = match.group("name").strip()
            version = match.group("version").strip()
            key = f"{name.lower()}:{version}"
            if key not in seen and len(name) >= 2:
                seen.add(key)
                technologies.append({"name": name, "version": version})
    return technologies[:100]


def extract_ports_from_assets(
    assets: list[str], ports: list[int] | None = None
) -> list[dict[str, Any]]:
    """Extract structured port/service data from asset strings and port list."""
    seen: set[int] = set()
    result: list[dict[str, Any]] = []
    for asset in assets:
        for match in _PORT_SERVICE_RE.finditer(asset):
            port = int(match.group("port"))
            if port in seen or port < 1 or port > 65535:
                continue
            seen.add(port)
            result.append({
                "port": port,
                "protocol": match.group("proto"),
                "service": match.group("service"),
                "detail": (match.group("detail") or "").strip()[:256],
            })

    for port_num in ports or []:
        if isinstance(port_num, int) and port_num not in seen and 0 < port_num <= 65535:
            seen.add(port_num)
            result.append({
                "port": port_num,
                "protocol": "tcp",
                "service": "unknown",
                "detail": "",
            })
    return sorted(result, key=lambda x: x["port"])[:500]


def extract_endpoints_from_assets(assets: list[str]) -> list[str]:
    """Extract URL paths / endpoints from asset strings."""
    seen: set[str] = set()
    endpoints: list[str] = []
    for asset in assets:
        for match in _ENDPOINT_PATTERNS.finditer(asset):
            path = match.group(1).strip()
            if path not in seen and path not in ("/", "//"):
                seen.add(path)
                endpoints.append(path)
    return endpoints[:200]


def build_recon_context(
    *,
    assets: list[str],
    subdomains: list[str] | None = None,
    ports: list[int] | None = None,
    target: str = "",
    recon_summary: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build structured recon context dict for threat modeling enrichment.

    Merges data from ReconOutput fields and optional recon_pipeline_summary.
    """
    summary = recon_summary or {}

    technologies = extract_technologies_from_assets(assets)
    tech_combined = summary.get("technologies_combined") or {}
    if isinstance(tech_combined, dict):
        by_host = tech_combined.get("by_host") or {}
        if isinstance(by_host, dict):
            for _host, host_data in by_host.items():
                if not isinstance(host_data, dict):
                    continue
                for cat_key in ("technologies", "tech", "plugins"):
                    entries = host_data.get(cat_key)
                    if isinstance(entries, list):
                        for entry in entries:
                            if isinstance(entry, dict):
                                name = str(entry.get("name") or entry.get("technology") or "").strip()
                                version = str(entry.get("version") or "").strip()
                                if name:
                                    key = f"{name.lower()}:{version}"
                                    existing_keys = {
                                        f"{t['name'].lower()}:{t['version']}" for t in technologies
                                    }
                                    if key not in existing_keys:
                                        technologies.append({"name": name, "version": version})

    open_ports = extract_ports_from_assets(assets, ports)

    endpoints = extract_endpoints_from_assets(assets)
    summary_urls = summary.get("urls")
    if isinstance(summary_urls, list):
        seen_ep = set(endpoints)
        for url in summary_urls[:200]:
            path = str(url).split("?")[0].split("#")[0]
            if "/" in path:
                path_part = "/" + path.split("/", 3)[-1] if "://" in path else path
                if path_part not in seen_ep and path_part != "/":
                    seen_ep.add(path_part)
                    endpoints.append(path_part[:256])

    forms: list[dict[str, Any]] = []

    entry_points: list[dict[str, str]] = []
    for ep in endpoints:
        ep_lower = ep.lower()
        ep_type = "web_endpoint"
        if any(seg in ep_lower for seg in ("/api/", "/graphql", "/rest/", "/v1/", "/v2/")):
            ep_type = "api_endpoint"
        elif any(seg in ep_lower for seg in ("/login", "/signin", "/auth")):
            ep_type = "authentication"
        elif any(seg in ep_lower for seg in ("/upload", "/file", "/attach")):
            ep_type = "file_upload"
        elif any(seg in ep_lower for seg in ("/admin", "/dashboard", "/manage")):
            ep_type = "admin_panel"
        entry_points.append({"type": ep_type, "url": ep, "method": "GET"})

    context: dict[str, Any] = {
        "target": target[:2048],
        "technologies": technologies[:50],
        "open_ports": open_ports[:100],
        "endpoints": endpoints[:100],
        "forms": forms[:50],
        "entry_points": entry_points[:100],
        "subdomains": (subdomains or [])[:50],
    }
    return context


def format_recon_context_for_prompt(context: dict[str, Any]) -> str:
    """Format the structured recon context into a readable string for the LLM prompt."""
    parts: list[str] = []

    target = context.get("target", "")
    if target:
        parts.append(f"Target: {target}")

    technologies = context.get("technologies", [])
    if technologies:
        parts.append("\n=== DETECTED TECHNOLOGIES ===")
        for tech in technologies:
            version = tech.get("version", "")
            name = tech.get("name", "unknown")
            parts.append(f"  - {name}" + (f" v{version}" if version else ""))

    open_ports = context.get("open_ports", [])
    if open_ports:
        parts.append("\n=== OPEN PORTS & SERVICES ===")
        for port_info in open_ports:
            port = port_info.get("port", "?")
            service = port_info.get("service", "unknown")
            detail = port_info.get("detail", "")
            line = f"  - {port}/{port_info.get('protocol', 'tcp')} — {service}"
            if detail:
                line += f" ({detail})"
            parts.append(line)

    endpoints = context.get("endpoints", [])
    if endpoints:
        parts.append("\n=== DISCOVERED ENDPOINTS ===")
        for ep in endpoints[:50]:
            parts.append(f"  - {ep}")

    forms = context.get("forms", [])
    if forms:
        parts.append("\n=== DISCOVERED FORMS ===")
        for form in forms:
            url = form.get("url", "?")
            fields = form.get("fields", [])
            form_type = form.get("type", "general")
            parts.append(f"  - {url} [{form_type}] fields={fields}")

    entry_points = context.get("entry_points", [])
    if entry_points:
        parts.append("\n=== ENTRY POINTS ===")
        for ep in entry_points[:30]:
            parts.append(
                f"  - [{ep.get('type', 'web_endpoint')}] "
                f"{ep.get('method', 'GET')} {ep.get('url', '?')}"
            )

    subdomains = context.get("subdomains", [])
    if subdomains:
        parts.append(f"\n=== SUBDOMAINS ({len(subdomains)} found) ===")
        for sd in subdomains[:20]:
            parts.append(f"  - {sd}")
        if len(subdomains) > 20:
            parts.append(f"  ... and {len(subdomains) - 20} more")

    return "\n".join(parts) if parts else "No enriched recon context available."


def parse_threat_model_result(raw: dict[str, Any]) -> ThreatModelResult:
    """Parse LLM threat model JSON into structured ThreatModelResult.

    Gracefully handles missing/malformed fields — never raises for bad data.
    """
    tm = raw.get("threat_model") or raw
    if not isinstance(tm, dict):
        tm = {}

    attack_surface: list[AttackSurfaceItem] = []
    for item in tm.get("attack_surface") or []:
        if isinstance(item, str):
            attack_surface.append(AttackSurfaceItem(
                component=item[:256],
                type="service",
                exposure_level="external",
            ))
        elif isinstance(item, dict):
            attack_surface.append(AttackSurfaceItem(
                component=str(item.get("component") or item.get("name") or "")[:256],
                type=str(item.get("type") or "service")[:64],
                exposure_level=str(item.get("exposure_level") or "external")[:32],
                url=str(item.get("url") or "")[:512],
            ))

    threats: list[StrideThreat] = []
    for item in tm.get("threats") or []:
        if isinstance(item, str):
            threats.append(StrideThreat(
                category="I",
                description=item[:1024],
                component="general",
                likelihood="medium",
                impact="medium",
            ))
        elif isinstance(item, dict):
            threats.append(StrideThreat(
                category=str(item.get("category") or "I")[:2],
                description=str(item.get("description") or "")[:1024],
                component=str(item.get("component") or "general")[:256],
                likelihood=str(item.get("likelihood") or "medium")[:16],
                impact=str(item.get("impact") or "medium")[:16],
            ))

    cves: list[CveReference] = []
    for item in tm.get("cves") or []:
        if isinstance(item, str):
            cves.append(CveReference(
                cve_id=item[:20],
                technology="unknown",
                severity="medium",
                description="",
            ))
        elif isinstance(item, dict):
            cves.append(CveReference(
                cve_id=str(item.get("cve_id") or item.get("id") or "")[:20],
                technology=str(item.get("technology") or "")[:128],
                severity=str(item.get("severity") or "medium")[:16],
                description=str(item.get("description") or "")[:512],
            ))

    mitigations: list[dict[str, str]] = []
    for item in tm.get("mitigations") or []:
        if isinstance(item, str):
            mitigations.append({
                "threat_ref": "general",
                "recommendation": item[:1024],
                "priority": "medium",
            })
        elif isinstance(item, dict):
            mitigations.append({
                "threat_ref": str(item.get("threat_ref") or "general")[:256],
                "recommendation": str(item.get("recommendation") or "")[:1024],
                "priority": str(item.get("priority") or "medium")[:16],
            })

    return ThreatModelResult(
        attack_surface=attack_surface,
        threats=threats,
        cves=cves,
        mitigations=mitigations,
    )


def merge_threat_model_result_into_output(
    original: dict[str, Any],
    parsed: ThreatModelResult,
) -> dict[str, Any]:
    """Merge parsed ThreatModelResult back into the LLM output dict.

    Preserves any extra keys from the LLM while ensuring structured data is present.
    Falls back gracefully: if the original already has well-structured data, keeps it.
    """
    tm = original.get("threat_model")
    if not isinstance(tm, dict):
        tm = {}
    result = dict(tm)

    if parsed.attack_surface and (
        not result.get("attack_surface") or all(
            isinstance(x, str) for x in result.get("attack_surface", [])
        )
    ):
        result["attack_surface"] = [a.to_dict() for a in parsed.attack_surface]

    if parsed.threats and (
        not result.get("threats") or all(
            isinstance(x, str) for x in result.get("threats", [])
        )
    ):
        result["threats"] = [t.to_dict() for t in parsed.threats]

    if parsed.cves and (
        not result.get("cves") or all(
            isinstance(x, str) for x in result.get("cves", [])
        )
    ):
        result["cves"] = [c.to_dict() for c in parsed.cves]

    if parsed.mitigations and not result.get("mitigations"):
        result["mitigations"] = parsed.mitigations

    return {"threat_model": result}
