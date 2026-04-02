"""RECON-005 — deep port scan helpers and bundle (mocked KAL)."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import asyncio

import pytest

from src.recon.recon_deep_port_scan import (
    collect_hosts_for_deep_scan,
    merge_deep_ports_into_nmap_tool_result,
    parse_naabu_host_port_lines,
    parse_user_ports_csv,
    run_recon_deep_port_scan_bundle,
)
from src.recon.recon_runtime import ReconRuntimeConfig


def test_parse_naabu_host_port_lines() -> None:
    text = "10.0.0.1:80\nsub.example.com:443\n"
    m = parse_naabu_host_port_lines(text)
    assert m["10.0.0.1"] == {80}
    assert m["sub.example.com"] == {443}


def test_parse_user_ports_csv_caps() -> None:
    assert parse_user_ports_csv("80,443", cap=10) == {80, 443}
    assert 80 in parse_user_ports_csv("80-82", cap=50)


def test_collect_hosts_respects_apex_and_cap() -> None:
    tool_results = {
        "subdomains_merged": {
            "stdout": json.dumps(["www.example.com", "evil.other.com", "a.example.com"]),
        }
    }
    h = collect_hosts_for_deep_scan("example.com", tool_results, max_hosts=2)
    assert h == ["example.com", "www.example.com"]


def test_merge_deep_ports_into_nmap_additive() -> None:
    tr: dict = {
        "nmap": {
            "structured": {"mode": "sandbox_cycle", "open_tcp_ports": ["80"]},
        }
    }
    merge_deep_ports_into_nmap_tool_result(
        tr,
        {"aggregate_tcp_ports": [443, 80]},
    )
    st = tr["nmap"]["structured"]
    assert set(st["open_tcp_ports"]) == {"80", "443"}
    assert "deep_port_enrichment" in st


@pytest.mark.asyncio
async def test_run_recon_deep_port_scan_skips_non_full() -> None:
    cfg = ReconRuntimeConfig(
        mode="active",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=True,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
    )
    out = await run_recon_deep_port_scan_bundle(
        "https://example.com",
        "example.com",
        "443",
        {},
        cfg,
        raw_sink=None,
        tenant_id=None,
        scan_id=None,
    )
    assert out == {}


@pytest.mark.asyncio
async def test_run_recon_deep_port_scan_bundle_mocked_nmap() -> None:
    cfg = ReconRuntimeConfig(
        mode="full",
        active_depth=1,
        enable_content_discovery=False,
        deep_port_scan=True,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
        deep_naabu_enabled=False,
        deep_max_hosts=1,
        deep_max_ports_per_host=10,
    )
    minimal_xml = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="test"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""
    tool_results: dict = {
        "nmap": {"structured": {"open_tcp_ports": ["80"], "mode": "legacy"}},
    }

    async def _fake_to_thread(fn, *args, **kwargs):  # noqa: ANN001
        if getattr(fn, "__name__", "") == "run_kal_mcp_tool":
            return {
                "success": True,
                "stdout": minimal_xml,
                "stderr": "",
                "return_code": 0,
                "execution_time": 0.01,
            }
        return await asyncio.to_thread(fn, *args, **kwargs)

    with (
        patch(
            "src.recon.recon_deep_port_scan.asyncio.to_thread",
            new_callable=AsyncMock,
            side_effect=_fake_to_thread,
        ),
        patch("src.recon.recon_deep_port_scan._tool_binary_visible", return_value=True),
        patch(
            "src.recon.recon_deep_port_scan.evaluate_kal_mcp_policy",
            return_value=type("D", (), {"allowed": True, "reason": "allowed"})(),
        ),
    ):
        out = await run_recon_deep_port_scan_bundle(
            "https://example.com",
            "example.com",
            "443",
            tool_results,
            cfg,
            raw_sink=None,
            tenant_id=None,
            scan_id=None,
        )

    assert "deep_port_scan" in out
    assert out["deep_port_scan"].get("success") is True
    merged = tool_results["nmap"]["structured"]
    assert "443" in merged.get("open_tcp_ports", [])
