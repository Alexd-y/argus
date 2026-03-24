"""VA-009 — XSS active-scan path: dalfox/xsstrike raw sink + high-CVSS finding (mocked I/O)."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle

ALF_NU_TARGET = "https://alf.nu/alert1?world=alert&level=alert0"


@pytest.mark.asyncio
async def test_va_active_scan_phase_xss_finding_triggers_raw_sink_for_dalfox(tmp_path: Path) -> None:
    """Dalfox job sinks stdout via sink_raw_text; normalized finding has alert(1) and CVSS >= 7."""
    from src.orchestration.handlers import _normalize_intel_finding
    from src.recon.vulnerability_analysis.active_scan.va_active_scan_phase import (
        run_va_active_scan_phase,
    )

    wl = tmp_path / "ffuf.txt"
    wl.write_text("x\n", encoding="utf-8")

    dalfox_row = {
        "url": ALF_NU_TARGET,
        "param": "world",
        "poc": "<script>alert(1)</script>",
        "severity": "high",
        "cvss_score": 7.5,
    }
    dalfox_stdout = json.dumps([dalfox_row], ensure_ascii=False)

    async def _fake_run_va_active_scan(**kwargs: object) -> dict[str, object]:
        tool = kwargs.get("tool_name", "")
        if tool == "dalfox":
            return {
                "exit_code": 0,
                "stdout": dalfox_stdout,
                "stderr": "",
                "duration_ms": 12,
                "tool_id": "dalfox",
                "error_reason": "",
            }
        return {
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "tool_id": str(tool),
            "error_reason": "",
        }

    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="eng-xss-1",
        target_id="alf-nu",
        entry_points=[],
        threat_scenarios=[],
        params_inventory=[
            {
                "url": "https://alf.nu/alert1",
                "param": "world",
                "value": "alert",
                "method": "GET",
            },
            {
                "url": "https://alf.nu/alert1",
                "param": "level",
                "value": "alert0",
                "method": "GET",
            },
        ],
        forms_inventory=[],
        intel_findings=[],
        live_hosts=[{"host": "alf.nu"}],
        tech_profile=[],
    )

    sink_mock = MagicMock()

    with (
        patch(
            "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.settings",
        ) as mock_settings,
        patch(
            "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.sink_raw_text",
            sink_mock,
        ),
        patch(
            "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.sink_raw_json",
            MagicMock(),
        ),
        patch(
            "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.run_va_active_scan",
            new_callable=AsyncMock,
            side_effect=_fake_run_va_active_scan,
        ),
    ):
        mock_settings.sandbox_enabled = True
        mock_settings.va_active_scan_tool_timeout_sec = 30.0
        mock_settings.ffuf_va_wordlist_path = str(wl)
        mock_settings.sqlmap_va_enabled = False
        mock_settings.va_ai_plan_enabled = False

        out = await run_va_active_scan_phase(
            bundle,
            tenant_id_raw="tenant-va009",
            scan_id_raw="scan-va009",
            va_raw_log=lambda _m: None,
        )

    dalfox_sink_calls = [
        c
        for c in sink_mock.call_args_list
        if "dalfox" in str(c.kwargs.get("artifact_type", ""))
    ]
    assert dalfox_sink_calls, "expected sink_raw_text for dalfox artifact types"

    intel = out.intel_findings or []
    assert intel, "expected intel findings from dalfox stdout"
    normalized = [_normalize_intel_finding(x) for x in intel if isinstance(x, dict)]
    xss_rows = [f for f in normalized if "xss" in (f.get("title") or "").lower() or f.get("cwe") == "CWE-79"]
    assert xss_rows
    assert xss_rows[0].get("cvss", 0) >= 7.0
    desc = (xss_rows[0].get("description") or "").lower()
    poc_blob = desc + (xss_rows[0].get("title") or "").lower()
    assert "alert(1)" in poc_blob or "alert(1)" in json.dumps(xss_rows[0]).lower()


@pytest.mark.asyncio
async def test_run_vuln_analysis_xss_pipeline_minio_sink_dalfox(tmp_path: Path) -> None:
    """Handler calls real active-scan phase with mocked runner + sink_raw_text (dalfox path)."""
    from src.orchestration.handlers import run_vuln_analysis
    from src.orchestration.phases import VulnAnalysisOutput
    from src.recon.vulnerability_analysis.active_scan import va_active_scan_phase as vmod

    wl = tmp_path / "ffuf.txt"
    wl.write_text("p\n", encoding="utf-8")

    dalfox_row = {
        "url": ALF_NU_TARGET,
        "param": "world",
        "poc": "<script>alert(1)</script>",
        "severity": "high",
        "cvss_score": 7.4,
    }
    dalfox_stdout = json.dumps([dalfox_row], ensure_ascii=False)

    async def _fake_run_va_active_scan(**kwargs: object) -> dict[str, object]:
        tool = kwargs.get("tool_name", "")
        if tool == "dalfox":
            return {
                "exit_code": 0,
                "stdout": dalfox_stdout,
                "stderr": "",
                "duration_ms": 5,
                "tool_id": "dalfox",
                "error_reason": "",
            }
        return {
            "exit_code": 0,
            "stdout": "",
            "stderr": "",
            "duration_ms": 0,
            "tool_id": str(tool),
            "error_reason": "",
        }

    sink_text = MagicMock()

    async def _delegating_phase(*args: object, **kwargs: object) -> object:
        with (
            patch.object(vmod, "sink_raw_text", sink_text),
            patch.object(vmod, "sink_raw_json", MagicMock()),
            patch.object(vmod, "run_va_active_scan", new_callable=AsyncMock, side_effect=_fake_run_va_active_scan),
        ):
            return await vmod.run_va_active_scan_phase(*args, **kwargs)

    with (
        patch("src.orchestration.handlers.settings") as mock_handlers_settings,
        patch(
            "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.settings",
        ) as mock_va_settings,
        patch(
            "src.recon.vulnerability_analysis.xsstrike_targets._live_host_scope",
            return_value=None,
        ),
        patch(
            "src.orchestration.handlers.run_va_active_scan_phase",
            new_callable=AsyncMock,
            side_effect=_delegating_phase,
        ),
        patch(
            "src.orchestration.handlers.ai_vuln_analysis",
            new_callable=AsyncMock,
            return_value=VulnAnalysisOutput(findings=[]),
        ),
        patch(
            "src.orchestration.handlers._extract_url_params_and_forms",
            new_callable=AsyncMock,
            return_value=(
                [
                    {
                        "url": "https://alf.nu/alert1",
                        "param": "world",
                        "value": "alert",
                        "method": "GET",
                    },
                ],
                [],
            ),
        ),
        patch("src.orchestration.handlers.run_web_vuln_heuristics", new_callable=AsyncMock, return_value=[]),
        patch("src.orchestration.handlers.RawPhaseSink"),
    ):
        mock_handlers_settings.sandbox_enabled = True
        mock_handlers_settings.ffuf_va_wordlist_path = str(wl)
        mock_handlers_settings.sqlmap_va_enabled = False
        mock_handlers_settings.va_ai_plan_enabled = False
        mock_va_settings.sandbox_enabled = True
        mock_va_settings.va_active_scan_tool_timeout_sec = 30.0
        mock_va_settings.ffuf_va_wordlist_path = str(wl)
        mock_va_settings.sqlmap_va_enabled = False
        mock_va_settings.va_ai_plan_enabled = False

        result = await run_vuln_analysis(
            threat_model={},
            assets=["alf.nu"],
            target=ALF_NU_TARGET,
            tenant_id="t-va009",
            scan_id="s-va009",
        )

    assert sink_text.called
    types_blob = " ".join(str(c.kwargs.get("artifact_type", "")) for c in sink_text.call_args_list)
    assert "dalfox" in types_blob or "xsstrike" in types_blob

    assert result.findings
    high = [f for f in result.findings if (f.get("cvss") or 0) >= 7.0]
    assert high
    blob = json.dumps(high[0], ensure_ascii=False).lower()
    assert "alert(1)" in blob
