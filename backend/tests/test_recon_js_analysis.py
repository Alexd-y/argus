"""RECON-007 — merged URL harvest, query params, JS URL filter, regex endpoints."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.recon.recon_js_analysis import (
    extract_endpoints_regex,
    extract_query_param_names,
    is_js_asset_url,
    merged_http_urls_from_tool_results,
    run_recon_js_analysis_bundle,
)


def test_extract_query_param_names_dedupes_keys() -> None:
    r = extract_query_param_names(
        [
            "https://a.example/x?foo=1&bar=2",
            "https://a.example/y?foo=9&baz=0",
            "https://a.example/z",
        ],
        max_urls=100,
    )
    assert set(r["unique_names"]) == {"bar", "baz", "foo"}
    assert r["urls_with_query"] == 2


def test_is_js_asset_url() -> None:
    assert is_js_asset_url("https://cdn.example/app.js?v=1")
    assert is_js_asset_url("https://x/module.mjs")
    assert not is_js_asset_url("https://x/page.html")


def test_extract_endpoints_regex_finds_paths() -> None:
    js = 'fetch("/api/v1/user"); const u = `/internal/x`; url: "/graphql"'
    eps = extract_endpoints_regex(js)
    assert "/api/v1/user" in eps
    assert "/internal/x" in eps
    assert "/graphql" in eps


def test_merged_http_urls_from_tool_results() -> None:
    tr = {
        "url_history_urls": {"urls": ["https://a.com/a?x=1", "https://a.com/b"]},
        "gau": {"stdout": "https://a.com/c\nhttps://b.com/x\n"},
    }
    m = merged_http_urls_from_tool_results(tr)
    assert "https://a.com/a?x=1" in m
    assert "https://a.com/c" in m


@pytest.mark.asyncio
async def test_run_recon_js_analysis_bundle_no_fetch_when_max_downloads_zero() -> None:
    from src.recon.recon_runtime import ReconRuntimeConfig

    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=True,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
    )
    tool_results = {
        "url_history_urls": {
            "urls": ["https://example.com/app.js?token=1", "https://example.com/page?sort=asc"],
        },
    }
    fake_settings = MagicMock()
    fake_settings.recon_tools_timeout = 60
    fake_settings.recon_js_max_merged_urls = 5000
    fake_settings.recon_js_max_js_urls = 50
    fake_settings.recon_js_max_downloads = 0
    fake_settings.recon_js_max_response_bytes = 1024
    fake_settings.recon_js_linkfinder_enabled = False
    fake_settings.recon_js_unfurl_enabled = False
    fake_settings.sandbox_enabled = False

    out = await run_recon_js_analysis_bundle(
        "https://example.com",
        "example.com",
        tool_results,
        cfg,
        raw_sink=None,
        tenant_id=None,
        scan_id=None,
        app_settings=fake_settings,
    )
    assert "js_analysis" in out
    ja = out["js_analysis"]
    assert "token" in ja["query_params"]["unique_names"]
    assert "sort" in ja["query_params"]["unique_names"]
    assert any("app.js" in u for u in ja["js_urls"])
    assert ja["deep"]["fetched"] == []


@pytest.mark.asyncio
async def test_run_recon_js_analysis_bundle_uploads_json_when_sink() -> None:
    from src.recon.recon_runtime import ReconRuntimeConfig

    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=True,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=100,
    )
    tool_results = {"url_history_urls": {"urls": ["https://example.com/a.js"]}}
    sink = MagicMock()
    sink.upload_json = MagicMock()
    fake_settings = MagicMock()
    fake_settings.recon_tools_timeout = 60
    fake_settings.recon_js_max_merged_urls = 5000
    fake_settings.recon_js_max_js_urls = 50
    fake_settings.recon_js_max_downloads = 0
    fake_settings.recon_js_max_response_bytes = 1024
    fake_settings.recon_js_linkfinder_enabled = False
    fake_settings.recon_js_unfurl_enabled = False
    fake_settings.sandbox_enabled = False

    with patch(
        "src.recon.recon_js_analysis.validate_target_for_tool",
        return_value={"allowed": True, "reason": ""},
    ):
        await run_recon_js_analysis_bundle(
            "https://example.com",
            "example.com",
            tool_results,
            cfg,
            raw_sink=sink,
            tenant_id="t1",
            scan_id="s1",
            app_settings=fake_settings,
        )
    sink.upload_json.assert_called_once()
    assert sink.upload_json.call_args[0][0] == "js_analysis"
