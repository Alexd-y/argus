"""Unit tests for XSStrike adapter — parser, validation, normalization (XSS-001)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from src.recon.schemas.base import FindingType
from src.recon.vulnerability_analysis.xsstrike_adapter import (
    XSStrikeAdapter,
    normalize_xsstrike_findings,
    parse_xsstrike_stdout,
    severity_from_efficiency,
    strip_ansi,
    validate_xsstrike_target_url,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_strip_ansi_removes_color_codes() -> None:
    raw = "\x1b[91m\x1b[1m[+] \x1b[0mPayload: test"
    assert strip_ansi(raw) == "[+] Payload: test"


def test_severity_from_efficiency() -> None:
    assert severity_from_efficiency(100) == "critical"
    assert severity_from_efficiency(95) == "high"
    assert severity_from_efficiency(80) == "medium"
    assert severity_from_efficiency(40) == "low"
    assert severity_from_efficiency(None) == "medium"


def test_validate_xsstrike_target_url_ok() -> None:
    u = validate_xsstrike_target_url("https://example.com/path?x=1")
    assert u.startswith("https://example.com")


def test_validate_xsstrike_target_url_rejects_scheme() -> None:
    with pytest.raises(ValueError, match="http or https"):
        validate_xsstrike_target_url("javascript:alert(1)")


def test_validate_xsstrike_target_url_rejects_localhost() -> None:
    with pytest.raises(ValueError):
        validate_xsstrike_target_url("http://localhost/test")


def test_parse_xsstrike_stdout_single() -> None:
    raw = _read_fixture("xsstrike_single_payload.txt")
    findings = parse_xsstrike_stdout(raw, "https://example.com/search?q=a")
    assert len(findings) == 1
    assert findings[0]["type"] == "XSS"
    assert findings[0]["url"] == "https://example.com/search?q=a"
    assert findings[0]["param"] == "q"
    assert "<svg/onload=alert(1)>" in findings[0]["poc"]
    assert findings[0]["severity"] == "critical"
    assert findings[0]["efficiency"] == 100
    assert findings[0]["confidence_level"] == 6


def test_parse_xsstrike_stdout_two_params() -> None:
    raw = _read_fixture("xsstrike_two_params.txt")
    findings = parse_xsstrike_stdout(raw, "https://app.example/item")
    assert len(findings) == 2
    assert findings[0]["param"] == "id"
    assert findings[0]["severity"] == "medium"
    assert findings[1]["param"] == "name"
    assert findings[1]["severity"] == "critical"


def test_normalize_xsstrike_findings_shape() -> None:
    raw = [
        {
            "type": "XSS",
            "url": "https://x.test",
            "param": "p",
            "poc": "<x>",
            "severity": "high",
            "efficiency": 96,
            "confidence_level": 5,
        }
    ]
    norm = normalize_xsstrike_findings(raw)
    assert len(norm) == 1
    assert norm[0]["finding_type"] == FindingType.VULNERABILITY
    assert norm[0]["source_tool"] == "xsstrike"
    assert norm[0]["data"]["type"] == "XSS"
    assert norm[0]["data"]["url"] == "https://x.test"
    assert norm[0]["data"]["param"] == "p"
    assert norm[0]["data"]["poc"] == "<x>"
    assert norm[0]["data"]["severity"] == "high"


@pytest.mark.asyncio
async def test_adapter_raw_output_mode() -> None:
    adapter = XSStrikeAdapter()
    fixture = _read_fixture("xsstrike_single_payload.txt")
    out = await adapter.run(
        "https://example.com/search?q=a",
        {"raw_output": fixture},
    )
    assert len(out) == 1
    assert out[0]["data"]["severity"] == "critical"


@pytest.mark.asyncio
async def test_adapter_run_with_capture_returns_stdout() -> None:
    adapter = XSStrikeAdapter()
    fixture = _read_fixture("xsstrike_single_payload.txt")
    findings, stdout, stderr = await adapter.run_with_capture(
        "https://example.com/search?q=a",
        {"raw_output": fixture},
    )
    assert len(findings) == 1
    assert "Payload:" in stdout
    assert stderr == ""


@pytest.mark.asyncio
async def test_adapter_run_with_mocked_subprocess(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = XSStrikeAdapter()
    fixture = _read_fixture("xsstrike_single_payload.txt")

    monkeypatch.setattr(
        "src.recon.vulnerability_analysis.xsstrike_adapter.XSStrikeAdapter.is_available",
        lambda _self, **_: True,
    )
    monkeypatch.setattr(
        "src.recon.vulnerability_analysis.xsstrike_adapter._build_tool_argv",
        lambda url, _cfg: ["python3", "/tmp/xsstrike.py", "-u", url, "--skip"],
    )

    def fake_run_argv(argv, *, timeout, use_sandbox):
        _ = (timeout, use_sandbox)  # match _run_argv keyword interface from asyncio.to_thread
        assert "-u" in argv
        assert "https://scanme.example/page" in argv
        return fixture, "", 0, False, 0.1

    monkeypatch.setattr(
        "src.recon.vulnerability_analysis.xsstrike_adapter._run_argv",
        fake_run_argv,
    )

    out = await adapter.run("https://scanme.example/page", {"sandbox": False})
    assert len(out) == 1
    assert out[0]["data"]["param"] == "q"


def test_adapter_run_sync_bridge() -> None:
    """Document asyncio.run for non-async callers."""
    adapter = XSStrikeAdapter()
    fixture = _read_fixture("xsstrike_two_params.txt")
    out = asyncio.run(
        adapter.run("https://app.example/item", {"raw_output": fixture}),
    )
    assert len(out) == 2
