"""Applicability predicates: fingerprint × capability node."""

from __future__ import annotations

from src.capabilities.schemas import CapabilityNode, ProductionRisk
from src.quick.schemas import AssetFingerprint, FingerprintFact

_HTTP_PROTOCOLS = frozenset({"http", "https"})
_TLS_PROTOCOLS = frozenset({"https", "ssl", "tls"})
_WEB_SERVICES = frozenset({"http", "https", "www", "http-alt"})
_AD_SERVICES = frozenset({"ldap", "ldaps", "kerberos", "smb", "microsoft-ds"})
_LINUX_HINTS = frozenset({"linux", "ssh", "ubuntu", "debian", "centos", "rhel"})
_WINDOWS_HINTS = frozenset({"windows", "winrm", "rdp", "smb", "microsoft-ds"})


def _fact_value(fact: FingerprintFact | None) -> str:
    if fact is None or fact.value is None:
        return ""
    return fact.value.strip().lower()


def _fact_confidence(fact: FingerprintFact | None) -> float:
    if fact is None:
        return 0.0
    return float(fact.confidence)


def infer_asset_types(fingerprint: AssetFingerprint) -> frozenset[str]:
    """Map fingerprint facts onto capability asset_types. Always includes host."""
    types: set[str] = {"host"}
    protocol = _fact_value(fingerprint.protocol)
    service = _fact_value(fingerprint.service)
    product = _fact_value(fingerprint.product)
    cms = _fact_value(fingerprint.cms)
    framework = _fact_value(fingerprint.framework)
    os_hint = _fact_value(fingerprint.network_os_hints)
    tokens = {protocol, service, product, cms, framework, os_hint}

    if protocol in _HTTP_PROTOCOLS or service in _WEB_SERVICES:
        types.add("web_app")
    if _fact_value(fingerprint.api_hints):
        types.add("api")
    if protocol in _TLS_PROTOCOLS or _fact_value(fingerprint.tls_security_header_posture):
        types.add("web_app")
    if tokens & _AD_SERVICES or "ad" in os_hint or "windows" in os_hint:
        types.add("windows_host")
        if "ldap" in tokens or "kerberos" in tokens or "ad" in os_hint:
            types.add("ad_domain")
    if tokens & _LINUX_HINTS or "linux" in os_hint:
        types.add("linux_host")
    if tokens & _WINDOWS_HINTS:
        types.add("windows_host")
    if _fact_value(fingerprint.cloud_storage_admin_debug):
        types.add("cloud_asset")
        types.add("web_app")
    if service in {"binary", "malware"} or product in {"binary", "malware"}:
        types.add("binary")
        types.add("malware_sample")
    return frozenset(types)


def fingerprint_tokens(fingerprint: AssetFingerprint) -> frozenset[str]:
    """Lowercased product/tech tokens used for template and product matching."""
    values = (
        _fact_value(fingerprint.protocol),
        _fact_value(fingerprint.service),
        _fact_value(fingerprint.product),
        _fact_value(fingerprint.version),
        _fact_value(fingerprint.web_server),
        _fact_value(fingerprint.framework),
        _fact_value(fingerprint.cms),
        _fact_value(fingerprint.language),
        _fact_value(fingerprint.runtime),
    )
    return frozenset(token for token in values if token)


def mean_evidence_confidence(fingerprint: AssetFingerprint) -> float:
    facts = (
        fingerprint.protocol,
        fingerprint.service,
        fingerprint.product,
        fingerprint.version,
        fingerprint.web_server,
        fingerprint.framework,
        fingerprint.cms,
        fingerprint.language,
        fingerprint.runtime,
        fingerprint.waf_cdn_hints,
        fingerprint.authentication_surface,
        fingerprint.api_hints,
        fingerprint.cloud_storage_admin_debug,
        fingerprint.tls_security_header_posture,
        fingerprint.network_os_hints,
    )
    present = [fact for fact in facts if fact is not None]
    if not present:
        return 0.4
    return sum(_fact_confidence(fact) for fact in present) / len(present)


def exploitability_for_node(node: CapabilityNode) -> float:
    risk = node.production_risk
    if isinstance(risk, ProductionRisk):
        mapping = {
            ProductionRisk.PASSIVE: 0.35,
            ProductionRisk.ACTIVE: 0.55,
            ProductionRisk.INTRUSIVE: 0.7,
            ProductionRisk.DESTRUCTIVE: 0.0,
        }
        return mapping[risk]
    text = str(risk).strip().lower()
    mapping_text = {
        "passive": 0.35,
        "active": 0.55,
        "intrusive": 0.7,
        "destructive": 0.0,
    }
    return mapping_text.get(text, 0.5)


def expected_impact_for_node(node: CapabilityNode) -> float:
    node_id = node.id.lower()
    if "cve" in node_id or "auth" in node_id:
        return 0.85
    if "exposure" in node_id or "debug" in node_id:
        return 0.75
    if "tls" in node_id or "ssl" in node_id:
        return 0.55
    if "dns" in node_id or "fingerprint" in node_id:
        return 0.45
    return 0.6


def is_applicable(fingerprint: AssetFingerprint, node: CapabilityNode) -> bool:
    """Return True when the fingerprint satisfies the node's applicability predicate."""
    app = node.applicability
    inferred = infer_asset_types(fingerprint)
    required_assets = tuple(app.asset_types) or tuple(node.asset_types)
    if required_assets and not inferred.intersection(required_assets):
        return False

    protocol = _fact_value(fingerprint.protocol)
    if app.protocols:
        allowed = {item.strip().lower() for item in app.protocols}
        http_satisfies_http = protocol == "https" and "http" in allowed
        tls_overlap = protocol in _TLS_PROTOCOLS and bool(allowed & _TLS_PROTOCOLS)
        if protocol not in allowed and not http_satisfies_http and not tls_overlap:
            return False

    tokens = fingerprint_tokens(fingerprint)
    if app.products:
        wanted = {item.strip().lower() for item in app.products}
        if not tokens.intersection(wanted):
            return False
    if app.services:
        wanted_services = {item.strip().lower() for item in app.services}
        service = _fact_value(fingerprint.service)
        os_hint = _fact_value(fingerprint.network_os_hints)
        if service not in wanted_services and not (tokens | {os_hint}) & wanted_services:
            return False

    min_conf = float(app.min_confidence)
    if min_conf > 0.0 and mean_evidence_confidence(fingerprint) < min_conf:
        return False

    if app.require_tls:
        tls_value = _fact_value(fingerprint.tls_security_header_posture)
        if protocol not in _TLS_PROTOCOLS and not tls_value:
            return False
    if app.require_auth_surface and not _fact_value(fingerprint.authentication_surface):
        return False
    if app.require_api_hints and not _fact_value(fingerprint.api_hints):
        return False
    return not (
        app.require_cloud_exposure
        and not _fact_value(fingerprint.cloud_storage_admin_debug)
    )
