"""RECON-008 — asnmap summary + gowitness URL harvest (mocked subprocess / KAL)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.core.config import Settings
from src.recon.recon_asn_screenshots import (
    build_recon_asnmap_argv,
    collect_live_http_urls,
    parse_asnmap_stdout_structured,
    run_recon_asnmap_bundle,
    run_recon_gowitness_bundle,
)
from src.recon.recon_runtime import ReconRuntimeConfig


def test_build_asnmap_argv_rejects_invalid_apex() -> None:
    assert build_recon_asnmap_argv("") == []
    assert build_recon_asnmap_argv("../evil") == []
    assert build_recon_asnmap_argv("example.com") == [
        "asnmap",
        "-d",
        "example.com",
        "-silent",
        "-json",
    ]


def test_parse_asnmap_json_object() -> None:
    blob = '{"as_number": "15169","as_name":"Google","input":"example.com","as_range":["8.8.8.0/24"]}'
    s = parse_asnmap_stdout_structured(blob)
    assert s["row_count"] >= 1
    assert any(x.get("as_number") == "15169" for x in s["unique_asns"])


def test_collect_live_http_urls_from_httpx_jsonl() -> None:
    httpx_out = (
        '{"url":"https://a.example.com/","host":"a.example.com","status_code":200,"failed":false}\n'
        '{"url":"https://dead.example/","status_code":500,"failed":true}\n'
    )
    tr = {"httpx": {"stdout": httpx_out}}
    urls = collect_live_http_urls("https://seed.example", tr, max_urls=10)
    assert "https://a.example.com/" in urls
    assert "https://dead.example/" not in urls


@pytest.mark.asyncio
async def test_run_recon_asnmap_bundle_skips_when_disabled() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
        asnmap_enabled=False,
    )
    out = await run_recon_asnmap_bundle(
        "example.com",
        cfg,
        raw_sink=None,
        tenant_id=None,
        scan_id=None,
        app_settings=Settings(sandbox_enabled=True),
    )
    assert out == {}


@pytest.mark.asyncio
async def test_run_recon_asnmap_bundle_merges_summary() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
        asnmap_enabled=True,
    )
    fake = {
        "success": True,
        "stdout": '{"as_number":"13335","as_name":"CF","input":"example.com"}\n',
        "stderr": "",
        "return_code": 0,
        "execution_time": 0.1,
        "minio_keys": [],
    }
    sink = MagicMock()
    sink.upload_json = MagicMock()
    with patch(
        "src.recon.recon_asn_screenshots.run_kal_mcp_tool",
        return_value=fake,
    ):
        out = await run_recon_asnmap_bundle(
            "example.com",
            cfg,
            raw_sink=sink,
            tenant_id="t1",
            scan_id="s1",
            app_settings=Settings(sandbox_enabled=True),
        )
    assert "asnmap" in out
    assert "asn_summary" in out
    assert out["asn_summary"]["row_count"] >= 1
    sink.upload_json.assert_called_once()


@pytest.mark.asyncio
async def test_run_recon_gowitness_bundle_per_url_mocked() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=True,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
        gowitness_max_urls=2,
        gowitness_concurrency=2,
    )
    tr = {
        "httpx": {
            "stdout": '{"url":"https://x.example/","status_code":200,"failed":false}\n',
        }
    }
    with (
        patch(
            "src.recon.recon_asn_screenshots._tool_binary_visible",
            return_value=True,
        ),
        patch(
            "src.recon.recon_asn_screenshots._run_gowitness_one_sync",
            return_value={
                "url": "https://x.example/",
                "success": True,
                "minio_key": "tenant/scan/recon/raw/k.png",
                "error": None,
            },
        ),
    ):
        out = await run_recon_gowitness_bundle(
            "https://x.example/",
            tr,
            cfg,
            raw_sink=None,
            tenant_id="t",
            scan_id="s",
            app_settings=Settings(sandbox_enabled=True),
        )
    assert "gowitness_screenshots" in out
    assert out["gowitness_screenshots"]["summary"]["uploaded"] == 1
    assert out["gowitness_screenshots"]["artifacts"][0]["minio_key"]


@pytest.mark.asyncio
async def test_run_recon_gowitness_skips_when_screenshots_flag_off() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
    )
    out = await run_recon_gowitness_bundle(
        "https://x.example/",
        {},
        cfg,
        raw_sink=None,
        tenant_id=None,
        scan_id=None,
    )
    assert out == {}
