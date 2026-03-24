"""Unit tests for VA active-scan heuristics (OWASP2-005 bundle-derived hints)."""

from __future__ import annotations

from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle
from src.recon.vulnerability_analysis.active_scan.heuristics import (
    SCHEMA_VERSION,
    build_va_active_scan_heuristics,
)


def test_schema_version_constant_matches_output() -> None:
    bundle = VulnerabilityAnalysisInputBundle(engagement_id="e1")
    h = build_va_active_scan_heuristics(bundle)
    assert h["schema_version"] == SCHEMA_VERSION == "va_active_scan_heuristics_v2"


def test_ssrf_picks_extended_param_names() -> None:
    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="e1",
        params_inventory=[
            {"param": "webhook_url", "full_url": "https://a.example/x"},
            {"name": "x_forwarded_host", "full_url": "https://a.example/y"},
            {"query_param": "redirect_uri", "full_url": "https://a.example/z"},
        ],
    )
    h = build_va_active_scan_heuristics(bundle)
    ssrf = next(x for x in h["intel_overlay"] if x["category"] == "ssrf")
    params = ssrf["suggested_param_names"]
    assert "webhook_url" in params
    assert "x_forwarded_host" in params
    assert "redirect_uri" in params
    probe = h["ssrf_probe_suggestions"][0]
    assert "webhook_url" in probe["params"]


def test_headers_tls_contributes_suggested_header_names() -> None:
    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="e1",
        headers_tls={
            "summary": "x",
            "controls": [
                {
                    "statement_type": "observation",
                    "host": "https://example.com",
                    "x_forwarded_url": "https://evil",
                    "nested": {"X-Original-URL": "/admin"},
                }
            ],
        },
    )
    h = build_va_active_scan_heuristics(bundle)
    ssrf = next(x for x in h["intel_overlay"] if x["category"] == "ssrf")
    hdrs = ssrf["suggested_header_names"]
    assert "x-forwarded-url" in hdrs
    assert "x-original-url" in hdrs


def test_api_path_hints_from_inventories() -> None:
    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="e1",
        route_inventory=[{"path": "/static/logo.png"}],
        api_surface=[{"url": "https://api.example.com/v2/users"}],
        endpoint_inventory=[{"endpoint": "/internal/health"}],
    )
    h = build_va_active_scan_heuristics(bundle)
    paths = h["api_path_hints"][0]["paths"]
    assert "/v2/users" in paths
    assert "/internal/health" in paths
    api_ov = next(x for x in h["intel_overlay"] if x["category"] == "api_path_probe")
    assert "/v2/users" in api_ov["suggested_path_prefixes"]


def test_forms_inventory_field_names_for_redirect() -> None:
    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="e1",
        forms_inventory=[
            {
                "method": "GET",
                "page_url": "https://a.example/login",
                "fields": [
                    {"name": "post_logout_redirect_uri"},
                    {"name": "username"},
                ],
            }
        ],
    )
    h = build_va_active_scan_heuristics(bundle)
    redir = next(x for x in h["intel_overlay"] if x["category"] == "open_redirect")
    assert "post_logout_redirect_uri" in redir["suggested_param_names"]


def test_intel_overlay_preserves_required_fields() -> None:
    bundle = VulnerabilityAnalysisInputBundle(engagement_id="e1")
    h = build_va_active_scan_heuristics(bundle)
    for item in h["intel_overlay"]:
        assert item["source"] == "va_active_scan_heuristics"
        assert item["finding_type"] == "testing_hint"
        assert "category" in item
        assert "message" in item
