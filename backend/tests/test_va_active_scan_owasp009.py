"""OWASP-009 — Dalfox XSS normalized intel: critical severity, CVSS ≥ 7 (fixture, no network)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle
from src.recon.vulnerability_analysis.active_scan.dalfox_adapter import (
    normalize_dalfox_findings,
    parse_dalfox_stdout,
)
from src.recon.vulnerability_analysis.active_scan.va_active_scan_phase import (
    run_va_active_scan_phase,
)
from src.recon.vulnerability_analysis.xsstrike_targets import XsStrikeScanJob

ALF_NU_ALERT1_URL = "https://alf.nu/alert1?world=alert&level=alert0"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _read_fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def _alf_nu_dalfox_xss_hit(items: list[dict]) -> dict:
    dal = [
        x
        for x in items
        if isinstance(x, dict)
        and str(x.get("source_tool") or "") == "dalfox"
        and isinstance(x.get("data"), dict)
        and str(x["data"].get("type") or "").upper() == "XSS"
    ]
    assert dal, "expected merged dalfox XSS intel"
    hit = next(
        (
            d
            for d in dal
            if ALF_NU_ALERT1_URL in (d.get("data") or {}).get("url", "")
            or ALF_NU_ALERT1_URL in str(d.get("value", ""))
        ),
        None,
    )
    assert hit is not None, "expected alf.nu alert1 URL in dalfox intel"
    return hit


def _assert_alf_nu_alert1_xss_intel_critical_or_high(items: list[dict]) -> None:
    """Intel entry: XSS on alf.nu alert1, severity critical or high (mocked pipeline)."""
    hit = _alf_nu_dalfox_xss_hit(items)
    data = hit["data"]
    assert str(data.get("type") or "").upper() == "XSS"
    sev = str(data.get("severity") or "").lower()
    assert sev in ("critical", "high"), f"expected critical or high severity, got {sev!r}"
    if sev == "critical":
        cvss = data.get("cvss_score")
        assert isinstance(cvss, (int, float)) and float(cvss) >= 7.0


def _assert_critical_xss_intel(items: list[dict]) -> None:
    """Fixture path: remains critical with CVSS ≥ 7 (OWASP-009)."""
    hit = _alf_nu_dalfox_xss_hit(items)
    data = hit["data"]
    assert str(data.get("severity") or "").lower() == "critical"
    cvss = data.get("cvss_score")
    assert isinstance(cvss, (int, float)) and float(cvss) >= 7.0


def _artifact_types_from_sink_raw_text_mock(mock_sink: MagicMock) -> list[str]:
    return [
        str(c.kwargs.get("artifact_type") or "")
        for c in mock_sink.call_args_list
        if c.kwargs
    ]


def _assert_minio_artifact_types_include_dalfox_or_xsstrike(types: list[str]) -> None:
    assert any(
        "tool_dalfox" in at or "tool_xsstrike" in at for at in types
    ), f"expected artifact_type containing tool_dalfox or tool_xsstrike, got {types!r}"


def test_dalfox_fixture_parse_normalize_critical_cvss() -> None:
    raw = _read_fixture("dalfox_alf_nu_alert1_xss.jsonl")
    parsed = parse_dalfox_stdout(raw)
    assert len(parsed) >= 1
    norm = normalize_dalfox_findings(parsed)
    _assert_critical_xss_intel(norm)


@pytest.mark.asyncio
async def test_va_active_scan_phase_merges_dalfox_xss_intel_mocked() -> None:
    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="e",
        params_inventory=[
            {
                "param": "level",
                "full_url": ALF_NU_ALERT1_URL,
            }
        ],
    )
    log: list[str] = []
    fixture_stdout = _read_fixture("dalfox_alf_nu_alert1_xss.jsonl")
    mock_result = {
        "exit_code": 0,
        "stdout": fixture_stdout,
        "stderr": "",
        "duration_ms": 1,
        "tool_id": "dalfox",
        "error_reason": "",
    }
    jobs = [
        XsStrikeScanJob(
            url=ALF_NU_ALERT1_URL,
            post_data=None,
            source="params_inventory",
        )
    ]

    with patch("src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.settings") as s:
        s.sandbox_enabled = True
        s.va_active_scan_tool_timeout_sec = 30.0
        s.ffuf_va_wordlist_path = ""
        s.sqlmap_va_enabled = False
        with patch(
            "src.recon.vulnerability_analysis.active_scan.planner.collect_xsstrike_scan_jobs",
            return_value=jobs,
        ):
            with patch(
                "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.run_va_active_scan",
                new_callable=AsyncMock,
                return_value=mock_result,
            ):
                with patch(
                    "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.sink_raw_text",
                    new_callable=MagicMock,
                ) as mock_sink_text:
                    with patch(
                        "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.sink_raw_json",
                    ):
                        out = await run_va_active_scan_phase(
                            bundle,
                            tenant_id_raw="tenant-1",
                            scan_id_raw="job-owasp009",
                            va_raw_log=log.append,
                        )

    _assert_alf_nu_alert1_xss_intel_critical_or_high(out.intel_findings or [])
    text_artifact_types = _artifact_types_from_sink_raw_text_mock(mock_sink_text)
    _assert_minio_artifact_types_include_dalfox_or_xsstrike(text_artifact_types)


@pytest.mark.asyncio
async def test_va_active_scan_phase_alf_nu_minio_keys_via_upload_raw_artifact_mock() -> None:
    """MinIO key material: upload_raw_artifact receives artifact_type containing tool_dalfox (or xsstrike)."""
    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="e",
        params_inventory=[
            {
                "param": "level",
                "full_url": ALF_NU_ALERT1_URL,
            }
        ],
    )
    log: list[str] = []
    fixture_stdout = _read_fixture("dalfox_alf_nu_alert1_xss.jsonl")
    mock_result = {
        "exit_code": 0,
        "stdout": fixture_stdout,
        "stderr": "",
        "duration_ms": 1,
        "tool_id": "dalfox",
        "error_reason": "",
    }
    jobs = [
        XsStrikeScanJob(
            url=ALF_NU_ALERT1_URL,
            post_data=None,
            source="params_inventory",
        )
    ]

    with patch("src.recon.raw_artifact_sink.upload_raw_artifact", MagicMock(return_value="tenant/scan/key")) as mock_upload:
        with patch("src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.settings") as s:
            s.sandbox_enabled = True
            s.va_active_scan_tool_timeout_sec = 30.0
            s.ffuf_va_wordlist_path = ""
            s.sqlmap_va_enabled = False
            with patch(
                "src.recon.vulnerability_analysis.active_scan.planner.collect_xsstrike_scan_jobs",
                return_value=jobs,
            ):
                with patch(
                    "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.run_va_active_scan",
                    new_callable=AsyncMock,
                    return_value=mock_result,
                ):
                    out = await run_va_active_scan_phase(
                        bundle,
                        tenant_id_raw="tenant-1",
                        scan_id_raw="job-alf-nu-minio",
                        va_raw_log=log.append,
                    )

    _assert_alf_nu_alert1_xss_intel_critical_or_high(out.intel_findings or [])
    artifact_types = [
        str(c.kwargs.get("artifact_type") or "")
        for c in mock_upload.call_args_list
        if getattr(c, "kwargs", None)
    ]
    _assert_minio_artifact_types_include_dalfox_or_xsstrike(artifact_types)
