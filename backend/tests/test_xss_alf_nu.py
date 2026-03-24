"""XSS-004: alf.nu alert1 training target — parser/normalizer critical XSS (fixture, no network)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.recon.vulnerability_analysis.xsstrike_adapter import (
    XSStrikeAdapter,
    normalize_xsstrike_findings,
    parse_xsstrike_stdout,
)

ALF_NU_ALERT1_URL = "https://alf.nu/alert1?world=alert&level=alert0"

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_alf_nu_alert1_parse_and_normalize_critical_xss_level_param() -> None:
    raw = _read_fixture("xsstrike_alf_nu_alert1_level.txt")
    parsed = parse_xsstrike_stdout(raw, ALF_NU_ALERT1_URL)
    assert len(parsed) >= 1
    f0 = parsed[0]
    assert f0["type"] == "XSS"
    assert f0["severity"] == "critical"
    assert f0.get("param") == "level" or "alert1" in (f0.get("url") or "")

    norm = normalize_xsstrike_findings(parsed)
    assert len(norm) >= 1
    data = norm[0]["data"]
    assert data["type"] == "XSS"
    assert data["severity"] == "critical"
    assert data.get("param") == "level" or "alert1" in (data.get("url") or "")


@pytest.mark.asyncio
async def test_alf_nu_alert1_adapter_raw_output_critical_xss() -> None:
    raw = _read_fixture("xsstrike_alf_nu_alert1_level.txt")
    adapter = XSStrikeAdapter()
    findings = await adapter.run(ALF_NU_ALERT1_URL, {"raw_output": raw})
    assert len(findings) >= 1
    data = findings[0]["data"]
    assert data["type"] == "XSS"
    assert data["severity"] == "critical"
    assert data.get("param") == "level" or "alert1" in (data.get("url") or "")
