"""QUICK-003 — frozen Nuclei template selection: ids + sha256, repeatable digest."""

from __future__ import annotations

from src.execution_mode.mode import ExecutionMode
from src.nuclei.schemas import (
    NucleiTemplateManifest,
    TemplateSource,
    digest_nuclei_template_ids,
)
from src.nuclei.template_registry import NucleiTemplateRegistry
from src.quick.schemas import (
    AssetFingerprint,
    FingerprintFact,
    QuickProfileName,
    QuickScanConfig,
    SeverityFloor,
)
from src.quick.template_selector import QuickTemplateSelector

_ASSET_ID = "99999999-8888-7777-6666-555555555555"
_SHA256 = "b" * 64


def _config(**overrides) -> QuickScanConfig:
    base = dict(
        profile=QuickProfileName.BALANCED,
        wall_clock_budget_seconds=900,
        ai_budget_seconds=90,
        reserve_for_validation_percent=20,
        max_targets=10,
        max_urls_per_host=50,
        crawl_depth=2,
        severity_floor=SeverityFloor.MEDIUM,
        template_policy_id="quick-default",
    )
    base.update(overrides)
    return QuickScanConfig(**base)


def _fingerprint(**overrides) -> AssetFingerprint:
    base = dict(
        asset_id=_ASSET_ID,
        protocol=FingerprintFact(value="https", confidence=1.0),
        service=FingerprintFact(value="http", confidence=0.9),
        product=FingerprintFact(value="wordpress", confidence=0.9),
        version=FingerprintFact(value="6.4", confidence=0.8),
        cms=FingerprintFact(value="wordpress", confidence=0.9),
        web_server=FingerprintFact(value="nginx", confidence=0.7),
    )
    base.update(overrides)
    return AssetFingerprint(**base)


def _manifest(**overrides) -> NucleiTemplateManifest:
    base = dict(
        template_id="http-generic",
        version="1",
        source=TemplateSource.INTERNAL,
        sha256=_SHA256,
        signature="sig",
        verified=True,
        protocols=("http",),
        risk_level="passive",
        severity="high",
        execution_modes=("production", "lab_unrestricted", "quick"),
    )
    base.update(overrides)
    return NucleiTemplateManifest(**base)


def _registry(manifests: tuple[NucleiTemplateManifest, ...]) -> NucleiTemplateRegistry:
    registry = NucleiTemplateRegistry()
    for manifest in manifests:
        registry.register(
            manifest,
            mode=ExecutionMode.QUICK,
            skip_signature_gate=True,
        )
    return registry


def _selector(manifests: tuple[NucleiTemplateManifest, ...]) -> QuickTemplateSelector:
    return QuickTemplateSelector(registry=_registry(manifests))


def test_select_returns_frozen_ids_and_matching_sha256() -> None:
    manifests = (
        _manifest(template_id="zz-generic", protocols=("http",), severity="medium"),
        _manifest(
            template_id="aa-wordpress-6-4",
            product="wordpress",
            product_version="6.4",
            tags=("wordpress",),
            severity="critical",
        ),
        _manifest(
            template_id="mm-exposure",
            tags=("exposure", "misconfig"),
            severity="high",
        ),
    )
    selected = _selector(manifests).select(_fingerprint(), _config())
    assert selected.template_ids == (
        "aa-wordpress-6-4",
        "mm-exposure",
        "zz-generic",
    )
    assert selected.digest_sha256 == digest_nuclei_template_ids(selected.template_ids)
    assert len(selected.digest_sha256) == 64
    assert selected.profile_id == "quick-default"
    dumped = selected.model_dump()
    assert "argv" not in dumped
    assert "-t" not in dumped
    assert "cli" not in dumped


def test_repeat_select_yields_identical_digest() -> None:
    manifests = (
        _manifest(template_id="cve-2024-9999", tags=("cve",), severity="high"),
        _manifest(template_id="nginx-tech", tags=("nginx",), product="nginx", severity="medium"),
        _manifest(template_id="http-generic", protocols=("http",), severity="medium"),
    )
    selector = _selector(manifests)
    fingerprint = _fingerprint(
        product=FingerprintFact(value="nginx", confidence=0.9),
        version=None,
        cms=None,
        web_server=FingerprintFact(value="nginx", confidence=0.9),
    )
    first = selector.select(fingerprint, _config())
    second = selector.select(fingerprint, _config())
    assert first.template_ids == second.template_ids
    assert first.digest_sha256 == second.digest_sha256
    assert first == second


def test_register_order_does_not_change_digest() -> None:
    a = _manifest(template_id="b-template", tags=("exposure",), severity="high")
    b = _manifest(template_id="a-template", tags=("exposure",), severity="high")
    left = _selector((a, b)).select(_fingerprint(), _config())
    right = _selector((b, a)).select(_fingerprint(), _config())
    assert left.template_ids == right.template_ids == ("a-template", "b-template")
    assert left.digest_sha256 == right.digest_sha256


def test_severity_floor_excludes_info_and_low() -> None:
    manifests = (
        _manifest(template_id="info-only", severity="info", tags=("exposure",)),
        _manifest(template_id="low-only", severity="low", tags=("exposure",)),
        _manifest(template_id="medium-ok", severity="medium", tags=("exposure",)),
    )
    selected = _selector(manifests).select(
        _fingerprint(), _config(severity_floor=SeverityFloor.MEDIUM)
    )
    assert selected.template_ids == ("medium-ok",)


def test_unsigned_tenant_and_code_templates_excluded() -> None:
    manifests = (
        _manifest(
            template_id="tenant-unsigned",
            source=TemplateSource.TENANT,
            signature=None,
            verified=True,
            tags=("exposure",),
            severity="high",
        ),
        _manifest(
            template_id="code-rce",
            protocols=("code",),
            tags=("cve", "rce"),
            severity="critical",
        ),
        _manifest(template_id="http-ok", tags=("exposure",), severity="high"),
    )
    selected = _selector(manifests).select(_fingerprint(), _config())
    assert selected.template_ids == ("http-ok",)
    assert "tenant-unsigned" not in selected.template_ids
    assert "code-rce" not in selected.template_ids


def test_unverified_templates_not_in_pool() -> None:
    manifests = (
        _manifest(
            template_id="unverified",
            verified=False,
            tags=("exposure",),
            severity="high",
        ),
        _manifest(template_id="verified-ok", tags=("exposure",), severity="high"),
    )
    selected = _selector(manifests).select(_fingerprint(), _config())
    assert selected.template_ids == ("verified-ok",)


def test_oast_and_headless_deferred_until_signal_and_budget() -> None:
    manifests = (
        _manifest(
            template_id="oast-ssrf",
            requires_oast=True,
            tags=("exposure",),
            severity="high",
        ),
        _manifest(
            template_id="headless-xss",
            requires_headless=True,
            tags=("exposure",),
            severity="high",
        ),
        _manifest(template_id="plain-http", tags=("exposure",), severity="high"),
    )
    selector = _selector(manifests)
    fingerprint = _fingerprint()
    config = _config(enable_oast=True, enable_headless_on_signal=True)
    blocked = selector.select(
        fingerprint,
        config,
        oast_available=False,
        headless_signal=False,
        budget_allows_oast=True,
        budget_allows_headless=True,
    )
    assert blocked.template_ids == ("plain-http",)
    allowed = selector.select(
        fingerprint,
        config,
        oast_available=True,
        headless_signal=True,
        budget_allows_oast=True,
        budget_allows_headless=True,
    )
    assert allowed.template_ids == ("plain-http", "headless-xss", "oast-ssrf")
    assert allowed.digest_sha256 == digest_nuclei_template_ids(allowed.template_ids)


def test_empty_pool_still_has_stable_digest() -> None:
    selected = _selector(()).select(_fingerprint(), _config())
    assert selected.template_ids == ()
    assert selected.digest_sha256 == digest_nuclei_template_ids(())
    again = _selector(()).select(_fingerprint(), _config())
    assert again.digest_sha256 == selected.digest_sha256
