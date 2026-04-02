"""RECON-004 — http probe argv builders + tech merge (no subprocess)."""

import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from src.recon.recon_http_probe import (
    build_recon_httpx_argv,
    build_recon_nuclei_tech_argv,
    merge_http_probe_tech_stack,
)
from src.recon.recon_runtime import ReconRuntimeConfig


def test_build_recon_httpx_argv_respects_rate_limit() -> None:
    argv = build_recon_httpx_argv("https://a.example", 25)
    assert argv[0] == "httpx"
    assert "-u" in argv
    assert argv[argv.index("-u") + 1] == "https://a.example"
    assert argv[argv.index("-rate-limit") + 1] == "25"


def test_build_recon_nuclei_tech_argv_default_tags() -> None:
    argv = build_recon_nuclei_tech_argv(
        "https://b.example",
        rate_limit_rps=8,
        tags_csv="",
        templates_csv="",
    )
    assert argv[0] == "nuclei"
    assert "-tags" in argv
    assert argv[argv.index("-tags") + 1] == "tech"
    assert argv[argv.index("-rate-limit") + 1] == "8"


def test_build_recon_nuclei_tech_argv_templates_override() -> None:
    argv = build_recon_nuclei_tech_argv(
        "https://c.example",
        rate_limit_rps=3,
        tags_csv="ignored",
        templates_csv="http/technologies/tech-detect.yaml",
    )
    assert "-t" in argv
    assert "http/technologies/tech-detect.yaml" in argv


def test_merge_http_probe_combines_sources() -> None:
    hx_line = json.dumps(
        {
            "url": "https://x.example/",
            "host": "x.example",
            "tech": ["nginx"],
            "server": "nginx",
        }
    )
    ww = json.dumps(
        {
            "target": "https://x.example/",
            "plugins": {
                "HTTPServer": {"string": ["nginx"]},
                "PHP": {"version": ["8.1"]},
            },
        }
    )
    nuc_line = json.dumps(
        {
            "template-id": "php-detect",
            "matched-at": "https://x.example/",
            "info": {"name": "PHP Detected"},
        }
    )
    merged = merge_http_probe_tech_stack(
        httpx_stdout=hx_line,
        whatweb_stdout=ww,
        nuclei_stdout=nuc_line + "\n",
        primary_host="x.example",
    )
    hosts = merged.get("by_host") or {}
    assert "x.example" in hosts
    assert merged.get("tech_stack", {}).get("merged_entry_count", 0) >= 1
    flat = merged.get("technologies") or []
    blob = json.dumps(flat).lower()
    assert "nginx" in blob or "php" in blob


@pytest.mark.asyncio
async def test_run_recon_http_probe_bundle_skips_bad_target() -> None:
    from src.recon.recon_http_probe import run_recon_http_probe_bundle

    cfg = ReconRuntimeConfig(
        mode="active",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
    )
    out = await run_recon_http_probe_bundle(
        "not-a-url",
        cfg,
        raw_sink=None,
        tenant_id=None,
        scan_id=None,
    )
    assert out == {}


@pytest.mark.asyncio
async def test_run_recon_http_probe_bundle_merges_with_mocks() -> None:
    from src.core.config import Settings
    from src.recon.recon_http_probe import run_recon_http_probe_bundle

    cfg = ReconRuntimeConfig(
        mode="active",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
    )
    fake_settings = Settings(sandbox_enabled=False)
    allowed = SimpleNamespace(allowed=True, reason="allowed")

    def fake_run_kal_mcp_tool(**kwargs: object) -> dict:
        argv = kwargs.get("argv") or []
        cmd = str(argv[0]) if argv else ""
        if cmd == "httpx":
            stdout = json.dumps({"url": "https://h.example/", "host": "h.example", "tech": ["Apache"]})
        elif cmd == "whatweb":
            stdout = '{"target":"https://h.example/","plugins":{"HTTPServer":{"string":["Apache"]}}}'
        else:
            stdout = ""
        return {
            "success": True,
            "stdout": stdout,
            "stderr": "",
            "return_code": 0,
            "execution_time": 0.01,
            "policy_reason": None,
            "minio_keys": [],
        }

    with (
        patch("src.recon.recon_http_probe._tool_binary_visible", return_value=True),
        patch("src.recon.recon_http_probe.evaluate_kal_mcp_policy", return_value=allowed),
        patch("src.recon.recon_http_probe.evaluate_va_active_scan_tool_policy", return_value=allowed),
        patch("src.recon.recon_http_probe.run_kal_mcp_tool", side_effect=fake_run_kal_mcp_tool),
    ):
        out = await run_recon_http_probe_bundle(
            "https://h.example/",
            cfg,
            raw_sink=None,
            tenant_id=None,
            scan_id=None,
            app_settings=fake_settings,
        )

    assert "httpx" in out
    assert "http_probe_tech_stack" in out
    assert out["http_probe_tech_stack"]["technologies"]
