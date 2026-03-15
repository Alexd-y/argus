"""CSV report builders for recon data — asset, service, API, parameter inventories."""

import csv
import io
import logging
from urllib.parse import urlparse

from app.schemas.recon.stage3_readiness import ROUTE_CLASSIFICATION_CSV_COLUMNS

from src.db.models_recon import NormalizedFinding

logger = logging.getLogger(__name__)

# Path-to-classification mapping for route_classification when route_inventory has no classification.
# /login, /signin -> auth; /admin -> admin; etc.
_PATH_CLASSIFICATION_MAP: list[tuple[str, str]] = [
    ("login", "login_flow"),
    ("signin", "login_flow"),
    ("reset", "password_reset_flow"),
    ("forgot", "password_reset_flow"),
    ("contact", "contact_flow"),
    ("portal", "portal_flow"),
    ("admin", "admin_flow"),
    ("account", "account_flow"),
    ("user", "user_flow"),
]


def _derive_classification_from_path(path_or_url: str) -> str:
    """Derive classification from path/URL when route_inventory has no classification column."""
    lowered = (path_or_url or "").lower()
    for marker, cls in _PATH_CLASSIFICATION_MAP:
        if marker in lowered:
            return cls
    return "public_page"


def build_asset_inventory(findings: list[NormalizedFinding]) -> str:
    """Build asset_inventory.csv from normalized findings."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([
        "asset", "type", "environment", "ip", "cname", "status",
        "technologies", "cdn_waf", "priority", "source", "notes",
    ])

    subdomain_findings = [f for f in findings if f.finding_type == "subdomain"]
    url_findings = [f for f in findings if f.finding_type == "url"]
    ip_findings = [f for f in findings if f.finding_type == "ip_address"]
    tech_map = _build_tech_map(findings)

    seen_assets = set()

    for f in subdomain_findings:
        data = f.data or {}
        asset = data.get("subdomain", f.value)
        if asset in seen_assets:
            continue
        seen_assets.add(asset)
        techs = tech_map.get(asset, [])
        writer.writerow([
            asset, "subdomain", "", "", "",
            "verified" if f.is_verified else "unverified",
            "; ".join(techs), "", "medium", f.source_tool, "",
        ])

    for f in ip_findings:
        data = f.data or {}
        asset = data.get("ip", f.value)
        if asset in seen_assets:
            continue
        seen_assets.add(asset)
        writer.writerow([
            asset, "ip", "",
            asset, "",
            "live" if f.is_verified else "resolved",
            "", data.get("cdn_name", ""),
            "medium", f.source_tool,
            data.get("org", ""),
        ])

    for f in url_findings:
        data = f.data or {}
        url = data.get("url", f.value)
        status_code = data.get("status_code", "")
        writer.writerow([
            url, "url", "", "", "",
            str(status_code),
            "", "", "medium", f.source_tool,
            data.get("title", ""),
        ])

    return output.getvalue()


def build_service_inventory(findings: list[NormalizedFinding]) -> str:
    """Build service_inventory.csv from service findings."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([
        "host", "ip", "port", "protocol", "service", "version",
        "banner", "expected", "risk_level", "source", "notes",
    ])

    for f in findings:
        if f.finding_type != "service":
            continue
        data = f.data or {}
        writer.writerow([
            data.get("ip", ""), data.get("ip", ""),
            data.get("port", ""), data.get("protocol", "tcp"),
            data.get("service_name", ""), data.get("version", ""),
            data.get("banner", ""),
            "yes" if data.get("is_expected", True) else "no",
            data.get("risk_level", "info"),
            f.source_tool, "",
        ])

    return output.getvalue()


def build_api_inventory(findings: list[NormalizedFinding]) -> str:
    """Build api_inventory.csv from API endpoint findings."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([
        "host", "endpoint", "version", "method", "auth_required",
        "source", "category", "priority", "notes",
    ])

    for f in findings:
        if f.finding_type != "api_endpoint":
            continue
        data = f.data or {}
        writer.writerow([
            data.get("base_url", ""), data.get("path", ""),
            data.get("api_version", ""), data.get("method", "GET"),
            "yes" if data.get("auth_required") else "unknown",
            f.source_tool, "", "medium", "",
        ])

    return output.getvalue()


def build_param_inventory(findings: list[NormalizedFinding]) -> str:
    """Build param_inventory.csv from parameter findings."""
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow([
        "url", "parameter", "category", "sample_value",
        "likely_sensitive", "priority", "source", "notes",
    ])

    for f in findings:
        if f.finding_type != "parameter":
            continue
        data = f.data or {}
        examples = data.get("example_values", [])
        writer.writerow([
            data.get("url", ""), data.get("param_name", ""),
            data.get("category", ""), examples[0] if examples else "",
            "yes" if data.get("is_sensitive") else "no",
            "medium", f.source_tool, "",
        ])

    return output.getvalue()


def _build_tech_map(findings: list[NormalizedFinding]) -> dict[str, list[str]]:
    """Build host-to-technologies mapping."""
    tech_map: dict[str, list[str]] = {}
    for f in findings:
        if f.finding_type != "technology":
            continue
        data = f.data or {}
        host = data.get("url", "").split("//")[-1].split("/")[0].split(":")[0]
        name = data.get("name", "")
        if host and name:
            tech_map.setdefault(host, []).append(name)
    return tech_map


def build_route_classification_from_inventory(
    route_inventory_rows: list[dict],
    *,
    route_key: str = "route_path",
    url_key: str = "url",
    host_key: str = "host",
    classification_key: str = "classification",
    discovery_source_key: str = "discovery_source",
    evidence_ref_key: str = "evidence_ref",
) -> str:
    """Build route_classification.csv from route_inventory rows.

    Aggregates route, host, classification, discovery_source, evidence_ref.
    Derives classification from path patterns when route_inventory has no classification column
    (e.g. /login, /signin -> login_flow; /admin -> admin_flow).

    Args:
        route_inventory_rows: List of dicts from route_inventory.csv (or in-memory route_rows).
        route_key: Key for route path (default: route_path).
        url_key: Key for full URL, used when route_path missing (default: url).
        host_key: Key for host (default: host).
        classification_key: Key for classification; if empty, derived from path (default: classification).
        discovery_source_key: Key for discovery source (default: discovery_source).
        evidence_ref_key: Key for evidence ref (default: evidence_ref).

    Returns:
        CSV string with columns from ROUTE_CLASSIFICATION_CSV_COLUMNS.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL)
    writer.writerow(list(ROUTE_CLASSIFICATION_CSV_COLUMNS))

    seen: set[tuple[str, str]] = set()
    for row in route_inventory_rows:
        route_path = str(row.get(route_key, "") or "").strip()
        if not route_path:
            url = str(row.get(url_key, "") or "")
            if url:
                parsed = urlparse(url)
                route_path = parsed.path or "/"
        if not route_path:
            continue

        host = str(row.get(host_key, "") or "").strip()
        if not host:
            url = str(row.get(url_key, "") or "")
            if url:
                host = urlparse(url).netloc.lower()
        if not host:
            continue

        key = (route_path, host)
        if key in seen:
            continue
        seen.add(key)

        classification = str(row.get(classification_key, "") or "").strip()
        if not classification:
            classification = _derive_classification_from_path(
                row.get(url_key, "") or route_path
            )

        discovery_source = str(row.get(discovery_source_key, "") or "").strip()
        if not discovery_source:
            discovery_source = "unknown"

        evidence_ref = str(row.get(evidence_ref_key, "") or "").strip()

        writer.writerow([
            route_path,
            host,
            classification,
            discovery_source,
            evidence_ref,
        ])

    return output.getvalue()
