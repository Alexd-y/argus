"""RECON-003 — dns depth parsing, argv builder, runtime config, takeover hints (mocked I/O)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.core.config import Settings
from src.recon.recon_dns_depth import (
    build_dnsx_argv,
    build_takeover_hints,
    parse_dnsx_stdout,
    run_recon_dns_depth_bundle,
)
from src.recon.recon_runtime import ReconRuntimeConfig, build_recon_runtime_config


def test_parse_dnsx_stdout_flattens_json_lines() -> None:
    raw = (
        '{"host":"ex.com","a":["1.1.1.1"]}\n'
        '{"host":"ex.com","cname":["target.github.io"]}\n'
    )
    records, objs = parse_dnsx_stdout(raw)
    assert len(objs) == 2
    assert any(r["record_type"] == "A" and r["value"] == "1.1.1.1" for r in records)
    assert any(r["record_type"] == "CNAME" and "github.io" in r["value"] for r in records)


def test_build_takeover_hints_dangling_vs_resolved() -> None:
    records = [
        {"host": "www", "record_type": "CNAME", "value": "x.github.io"},
    ]
    hints = build_takeover_hints(records, [])
    assert len(hints) == 1
    assert hints[0]["hint_type"] == "potential_dangling_cname"

    follow = [{"host": "x.github.io", "record_type": "A", "value": "192.0.2.1"}]
    hints2 = build_takeover_hints(records, follow)
    assert hints2[0]["hint_type"] == "cloud_cname_target"


def test_build_dnsx_argv_respects_types_and_resolver() -> None:
    cfg = ReconRuntimeConfig(
        mode="passive",
        active_depth=0,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
        dnsx_record_types_csv="a,mx",
        dnsx_include_resp=True,
        dnsx_silent=True,
        dnsx_extra_flags=frozenset({"-wd"}),
    )
    with patch("src.recon.recon_dns_depth.settings") as m:
        m.recon_default_dns_resolver = "9.9.9.9,8.8.8.8"
        m.recon_dnsx_extra_flags = "-oc"
        argv = build_dnsx_argv("example.com", cfg)
    assert argv[:3] == ["dnsx", "-d", "example.com"]
    assert "-json" in argv
    assert "-a" in argv
    assert "-mx" in argv
    assert "-aaaa" not in argv
    assert "-resp" in argv
    assert "-silent" in argv
    assert "-r" in argv and "9.9.9.9" in argv
    assert "-wd" in argv
    assert "-oc" in argv


def test_build_recon_runtime_config_nested_dns_depth() -> None:
    cfg = build_recon_runtime_config(
        {
            "recon": {
                "dns_depth_enabled": False,
                "dns_depth_dig_deep": True,
                "dnsx_record_types": "a,cname",
                "dnsx_extra_flags": ["-silent", "-wd"],
            }
        },
        app_settings=Settings(),
    )
    assert cfg.dns_depth_enabled is False
    assert cfg.dns_depth_dig_deep is True
    assert "a" in cfg.dnsx_record_types_csv and "cname" in cfg.dnsx_record_types_csv
    assert "-silent" in (cfg.dnsx_extra_flags or frozenset())


@pytest.mark.asyncio
async def test_run_recon_dns_depth_bundle_disabled_returns_empty() -> None:
    cfg = ReconRuntimeConfig(
        mode="passive",
        active_depth=0,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
        dns_depth_enabled=False,
    )
    out = await run_recon_dns_depth_bundle("https://example.com", cfg, raw_sink=None)
    assert out == {}


@pytest.mark.asyncio
async def test_run_recon_dns_depth_bundle_uploads_and_merges_tool_shape() -> None:
    cfg = ReconRuntimeConfig(
        mode="passive",
        active_depth=0,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
        dns_depth_enabled=True,
        dns_depth_takeover_hints=False,
        dns_depth_dig_deep=False,
    )
    dnsx_out = {
        "success": True,
        "stdout": '{"host":"example.com","a":["93.184.216.34"]}\n',
        "stderr": "",
        "return_code": 0,
        "execution_time": 0.01,
    }
    sink = MagicMock()
    sink.upload_json = MagicMock()
    sink.upload_text = MagicMock()

    with (
        patch("src.recon.recon_dns_depth.build_dnsx_argv", return_value=["dnsx", "-d", "example.com", "-json", "-a"]),
        patch("src.recon.recon_dns_depth._run_dnsx_argv", return_value=dnsx_out),
    ):
        out = await run_recon_dns_depth_bundle("https://example.com", cfg, raw_sink=sink)

    assert "dnsx" in out
    assert "dns_depth" in out
    assert out["dns_depth"]["success"] is True
    structured = out["dns_depth"].get("structured")
    assert isinstance(structured, dict)
    assert structured.get("apex") == "example.com"
    assert any(r.get("record_type") == "A" for r in structured.get("records", []))
    sink.upload_json.assert_called_once()
    sink.upload_text.assert_called_once()


@pytest.mark.asyncio
async def test_run_recon_dns_depth_bundle_inner_failure_is_soft() -> None:
    cfg = ReconRuntimeConfig(
        mode="passive",
        active_depth=0,
        enable_content_discovery=False,
        deep_port_scan=False,
        js_analysis=False,
        screenshots=False,
        tool_selection=None,
        wordlist_path="",
        rate_limit_rps=10,
        dns_depth_enabled=True,
        dns_depth_takeover_hints=False,
    )
    with (
        patch("src.recon.recon_dns_depth.build_dnsx_argv", return_value=["dnsx", "-d", "example.com", "-json"]),
        patch("src.recon.recon_dns_depth._run_dnsx_argv", side_effect=RuntimeError("boom")),
    ):
        out = await run_recon_dns_depth_bundle("https://example.com", cfg, raw_sink=None)
    assert out["dns_depth"]["success"] is False
    assert "failed" in (out["dns_depth"].get("stderr") or "").lower()
