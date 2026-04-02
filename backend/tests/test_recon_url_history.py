"""RECON-006 — URL history helpers + bundle (mocked kal)."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from src.recon.recon_runtime import ReconRuntimeConfig
from src.recon.recon_url_history import (
    build_gau_argv,
    build_katana_argv,
    build_waybackurls_argv,
    filter_surface_urls,
    is_probably_static_asset_url,
    merge_dedupe_urls,
    parse_url_lines_from_text,
    parse_urls_from_katana_jsonl,
    run_recon_url_history_bundle,
    url_in_scope,
)


def test_url_in_scope_strict_subdomain() -> None:
    assert url_in_scope("https://app.example.com/x", "example.com", scope_strict=True) is True
    assert url_in_scope("https://evil.com/x", "example.com", scope_strict=True) is False


def test_url_in_scope_non_strict_allows_foreign_host() -> None:
    assert url_in_scope("https://evil.com/x", "example.com", scope_strict=False) is True


def test_static_asset_filter() -> None:
    assert is_probably_static_asset_url("https://x.com/a/style.css") is True
    assert is_probably_static_asset_url("https://x.com/api/user") is False


def test_merge_dedupe_urls_order() -> None:
    assert merge_dedupe_urls(["https://a.com/1", "https://a.com/1"], ["https://a.com/2"]) == [
        "https://a.com/1",
        "https://a.com/2",
    ]


def test_parse_katana_jsonl() -> None:
    raw = '{"url":"https://ex.com/p"}\nnot-json\n{"url":"https://ex.com/q"}\n'
    assert parse_urls_from_katana_jsonl(raw) == ["https://ex.com/p", "https://ex.com/q"]


def test_parse_url_lines_from_text() -> None:
    t = "  https://a.com/x  \nftp://no\nhttps://b.com/y"
    assert parse_url_lines_from_text(t) == ["https://a.com/x", "https://b.com/y"]


def test_build_argv_guards() -> None:
    assert build_gau_argv("example.com") == ["gau", "example.com"]
    assert build_gau_argv("") == []
    assert build_waybackurls_argv("bad/host") == []
    assert build_katana_argv("not-a-url", depth=2, rate_limit_rps=5) == []


def test_filter_surface_urls_dedupes() -> None:
    u = [
        "https://ex.com/a",
        "https://ex.com/a/",
        "https://ex.com/b.css",
        "https://other.com/z",
    ]
    got = filter_surface_urls(
        u,
        apex_domain="ex.com",
        scope_strict=True,
        drop_static_assets=True,
    )
    assert "https://other.com/z" not in got
    assert all("ex.com" in x for x in got)
    assert not any(x.endswith(".css") for x in got)


@pytest.mark.asyncio
async def test_run_recon_url_history_bundle_merges_and_uploads_json() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=2,
        enable_content_discovery=True,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=5,
    )

    def _fake_upload_json(_t: str, _o: object) -> None:
        return None

    def _fake_upload_text(_t: str, _s: str, ext: str = "txt") -> None:
        return None

    class _Sink:
        upload_json = _fake_upload_json
        upload_text = _fake_upload_text

    def fake_kal(**_kw: object) -> dict[str, object]:
        argv = _kw.get("argv")
        if not isinstance(argv, list) or not argv:
            return {"success": True, "stdout": "", "stderr": "", "return_code": 0}
        name = str(argv[0])
        if name == "gau":
            return {"success": True, "stdout": "https://ex.com/old\n", "stderr": "", "return_code": 0}
        if name == "waybackurls":
            return {"success": True, "stdout": "https://ex.com/old\nhttps://ex.com/other\n", "stderr": "", "return_code": 0}
        if name == "katana":
            return {
                "success": True,
                "stdout": '{"url":"https://ex.com/crawl"}\n',
                "stderr": "",
                "return_code": 0,
            }
        return {"success": True, "stdout": "", "stderr": "", "return_code": 0}

    sink = _Sink()
    with (
        patch("src.recon.recon_url_history.run_kal_mcp_tool", side_effect=fake_kal),
        patch("src.recon.recon_url_history._tool_binary_visible", return_value=True),
    ):
        out = await run_recon_url_history_bundle(
            "https://ex.com/",
            "ex.com",
            cfg,
            raw_sink=sink,
            tenant_id="t1",
            scan_id="s1",
        )

    assert "gau" in out and "waybackurls" in out and "katana" in out
    bundle = out.get("url_history_urls")
    assert isinstance(bundle, dict)
    urls = bundle.get("urls")
    assert isinstance(urls, list)
    assert "https://ex.com/crawl" in urls
    assert bundle.get("counts", {}).get("filtered") == len(urls)


@pytest.mark.asyncio
async def test_run_recon_url_history_skips_katana_when_depth_zero() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=0,
        enable_content_discovery=True,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=5,
    )
    calls: list[str] = []

    def fake_kal(*, argv: list[str], **_kw: object) -> dict[str, object]:
        calls.append(str(argv[0]) if argv else "")
        return {"success": True, "stdout": "", "stderr": "", "return_code": 0}

    with (
        patch("src.recon.recon_url_history.run_kal_mcp_tool", side_effect=fake_kal),
        patch("src.recon.recon_url_history._tool_binary_visible", return_value=True),
    ):
        await run_recon_url_history_bundle(
            "https://ex.com/",
            "ex.com",
            cfg,
            raw_sink=None,
            tenant_id=None,
            scan_id=None,
        )

    assert "gau" in calls and "waybackurls" in calls
    assert "katana" not in calls
