"""QUICK-003 — fingerprint × capability applicability predicates."""

from __future__ import annotations

import pytest

from src.capabilities.schemas import (
    CapabilityApplicability,
    CapabilityFamily,
    CapabilityNode,
    ProductionRisk,
)
from src.quick.applicability import (
    expected_impact_for_node,
    exploitability_for_node,
    fingerprint_tokens,
    infer_asset_types,
    is_applicable,
    mean_evidence_confidence,
)
from src.quick.schemas import AssetFingerprint, FingerprintFact

_ASSET_ID = "99999999-8888-7777-6666-555555555555"


def _fact(value: str | None, confidence: float = 1.0) -> FingerprintFact:
    return FingerprintFact(value=value, confidence=confidence)


def _fingerprint(**overrides) -> AssetFingerprint:
    base = dict(asset_id=_ASSET_ID)
    base.update(overrides)
    return AssetFingerprint(**base)


def _node(**overrides) -> CapabilityNode:
    base = dict(
        id="web.application.cve.known_product",
        family=CapabilityFamily.WEB_APPLICATION,
        asset_types=("web_app",),
        production_risk=ProductionRisk.ACTIVE,
        tools=("nuclei",),
        quick_eligible=True,
        applicability=CapabilityApplicability(),
    )
    base.update(overrides)
    return CapabilityNode(**base)


def test_infer_asset_types_always_includes_host() -> None:
    types = infer_asset_types(_fingerprint())
    assert types == frozenset({"host"})


def test_infer_http_https_as_web_app() -> None:
    http_types = infer_asset_types(_fingerprint(protocol=_fact("http"), service=_fact("http")))
    https_types = infer_asset_types(_fingerprint(protocol=_fact("https"), service=_fact("https")))
    assert "web_app" in http_types
    assert "web_app" in https_types
    assert "host" in https_types


def test_infer_ad_linux_windows_and_cloud() -> None:
    ad = infer_asset_types(
        _fingerprint(service=_fact("ldap"), network_os_hints=_fact("windows ad"))
    )
    assert "windows_host" in ad
    assert "ad_domain" in ad
    linux = infer_asset_types(_fingerprint(network_os_hints=_fact("ubuntu linux")))
    assert "linux_host" in linux
    cloud = infer_asset_types(
        _fingerprint(
            protocol=_fact("https"),
            cloud_storage_admin_debug=_fact("s3-public"),
        )
    )
    assert "cloud_asset" in cloud
    assert "web_app" in cloud


def test_https_satisfies_http_protocol_requirement() -> None:
    node = _node(applicability=CapabilityApplicability(protocols=("http",)))
    https = _fingerprint(protocol=_fact("https"), service=_fact("http"))
    http = _fingerprint(protocol=_fact("http"), service=_fact("http"))
    ssh = _fingerprint(protocol=_fact("ssh"), service=_fact("ssh"))
    assert is_applicable(https, node) is True
    assert is_applicable(http, node) is True
    assert is_applicable(ssh, node) is False


def test_asset_type_mismatch_is_not_applicable() -> None:
    node = _node(
        asset_types=("linux_host",),
        applicability=CapabilityApplicability(asset_types=("linux_host",)),
    )
    web = _fingerprint(protocol=_fact("https"), service=_fact("http"))
    assert is_applicable(web, node) is False


def test_product_and_service_constraints() -> None:
    node = _node(
        applicability=CapabilityApplicability(
            protocols=("http", "https"),
            products=("wordpress",),
            services=("http",),
        )
    )
    matching = _fingerprint(
        protocol=_fact("https"),
        service=_fact("http"),
        cms=_fact("wordpress"),
    )
    wrong_product = _fingerprint(
        protocol=_fact("https"),
        service=_fact("http"),
        cms=_fact("drupal"),
    )
    assert is_applicable(matching, node) is True
    assert is_applicable(wrong_product, node) is False


def test_min_confidence_gate() -> None:
    node = _node(applicability=CapabilityApplicability(min_confidence=0.8))
    weak = _fingerprint(protocol=_fact("https", confidence=0.2))
    strong = _fingerprint(protocol=_fact("https", confidence=0.95))
    assert is_applicable(weak, node) is False
    assert is_applicable(strong, node) is True


def test_require_tls_auth_api_and_cloud_flags() -> None:
    tls_node = _node(applicability=CapabilityApplicability(require_tls=True))
    auth_node = _node(applicability=CapabilityApplicability(require_auth_surface=True))
    api_node = _node(applicability=CapabilityApplicability(require_api_hints=True))
    cloud_node = _node(applicability=CapabilityApplicability(require_cloud_exposure=True))
    bare_http = _fingerprint(protocol=_fact("http"), service=_fact("http"))
    https = _fingerprint(protocol=_fact("https"), service=_fact("http"))
    authed = _fingerprint(
        protocol=_fact("https"),
        authentication_surface=_fact("login-form"),
    )
    api = _fingerprint(protocol=_fact("https"), api_hints=_fact("openapi"))
    cloud = _fingerprint(
        protocol=_fact("https"),
        cloud_storage_admin_debug=_fact("bucket-list"),
    )
    assert is_applicable(bare_http, tls_node) is False
    assert is_applicable(https, tls_node) is True
    assert is_applicable(https, auth_node) is False
    assert is_applicable(authed, auth_node) is True
    assert is_applicable(https, api_node) is False
    assert is_applicable(api, api_node) is True
    assert is_applicable(https, cloud_node) is False
    assert is_applicable(cloud, cloud_node) is True


def test_mean_evidence_confidence_defaults_when_empty() -> None:
    assert mean_evidence_confidence(_fingerprint()) == pytest.approx(0.4)
    filled = _fingerprint(
        protocol=_fact("https", confidence=1.0),
        service=_fact("http", confidence=0.5),
    )
    assert mean_evidence_confidence(filled) == pytest.approx(0.75)


def test_fingerprint_tokens_are_lowercased_and_non_empty() -> None:
    tokens = fingerprint_tokens(
        _fingerprint(
            protocol=_fact("HTTPS"),
            product=_fact("Nginx"),
            version=_fact(""),
        )
    )
    assert "https" in tokens
    assert "nginx" in tokens
    assert "" not in tokens


@pytest.mark.parametrize(
    ("risk", "expected"),
    [
        (ProductionRisk.PASSIVE, 0.35),
        (ProductionRisk.ACTIVE, 0.55),
        (ProductionRisk.INTRUSIVE, 0.7),
        (ProductionRisk.DESTRUCTIVE, 0.0),
        ("passive", 0.35),
        ("unknown", 0.5),
    ],
)
def test_exploitability_for_node(risk: ProductionRisk | str, expected: float) -> None:
    assert exploitability_for_node(_node(production_risk=risk)) == expected


@pytest.mark.parametrize(
    ("node_id", "expected"),
    [
        ("web.application.cve.known_product", 0.85),
        ("web.application.auth.session", 0.85),
        ("web.application.exposure.sensitive_files", 0.75),
        ("web.application.tls.posture", 0.55),
        ("foundations.networking.dns_exposure", 0.75),
        ("foundations.networking.dns_resolve", 0.45),
        ("nuclei.protocol.http", 0.6),
    ],
)
def test_expected_impact_for_node(node_id: str, expected: float) -> None:
    assert expected_impact_for_node(_node(id=node_id)) == expected
