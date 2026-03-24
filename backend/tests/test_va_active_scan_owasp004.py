"""OWASP-004 — VA active scan adapters, heuristics, phase wiring (mocked I/O)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle
from src.recon.vulnerability_analysis.active_scan.dalfox_adapter import build_dalfox_argv
from src.recon.vulnerability_analysis.active_scan.ffuf_adapter import (
    build_ffuf_argv,
    inject_ffuf_marker_url,
    resolve_ffuf_wordlist_path,
)
from src.recon.vulnerability_analysis.active_scan.heuristics import build_va_active_scan_heuristics
from src.recon.vulnerability_analysis.active_scan.sqlmap_va_adapter import build_sqlmap_va_argv
from src.recon.vulnerability_analysis.active_scan.va_active_scan_phase import (
    run_va_active_scan_phase,
)
from src.recon.vulnerability_analysis.xsstrike_targets import XsStrikeScanJob


def test_build_dalfox_argv_valid() -> None:
    u = "https://example.com/page?q=1"
    assert build_dalfox_argv(u) == ["dalfox", "url", u]


def test_build_dalfox_argv_rejects_unsafe() -> None:
    assert build_dalfox_argv("") == []
    assert build_dalfox_argv("ftp://example.com/") == []
    assert build_dalfox_argv("https://ex ample.com/") == []


def test_inject_ffuf_marker_query() -> None:
    u = "https://example.com/x?p=1"
    m = inject_ffuf_marker_url(u)
    assert m is not None
    assert "FUZZ" in m
    assert m.startswith("https://")


def test_inject_ffuf_marker_path() -> None:
    m = inject_ffuf_marker_url("https://example.com/api/items")
    assert m is not None
    assert "FUZZ" in m


def test_build_ffuf_argv_requires_wordlist(tmp_path: Path) -> None:
    wl = tmp_path / "w.txt"
    wl.write_text("a\nb\n")
    argv = build_ffuf_argv("https://example.com/?x=1", wordlist_path=str(wl))
    assert argv[0] == "ffuf"
    assert "-u" in argv
    assert str(wl) in argv
    assert "-w" in argv


def test_resolve_ffuf_wordlist_path_explicit() -> None:
    assert resolve_ffuf_wordlist_path("/foo/bar") == "/foo/bar"


def test_build_sqlmap_va_argv_conservative() -> None:
    argv = build_sqlmap_va_argv("https://example.com/a?id=1", None)
    assert argv[:2] == ["sqlmap", "-u"]
    assert "--batch" in argv
    assert "--level" in argv and "1" in argv
    assert "--risk" in argv


def test_build_sqlmap_va_argv_with_post() -> None:
    argv = build_sqlmap_va_argv("https://example.com/login", "user=1&pass=2")
    assert "--data" in argv
    assert "user=1&pass=2" in argv


def test_heuristics_structure() -> None:
    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="e",
        params_inventory=[{"param": "redirect_url", "full_url": "https://a.com/x"}],
        forms_inventory=[{"method": "POST", "page_url": "https://a.com/", "action": "/"}],
        entry_points=[],
    )
    h = build_va_active_scan_heuristics(bundle)
    assert h["schema_version"] == "va_active_scan_heuristics_v2"
    assert "intel_overlay" in h
    assert len(h["intel_overlay"]) >= 5
    cats = {x["category"] for x in h["intel_overlay"]}
    assert "ssrf" in cats
    assert "open_redirect" in cats


@pytest.mark.asyncio
async def test_va_active_scan_phase_skips_without_sandbox() -> None:
    bundle = VulnerabilityAnalysisInputBundle(engagement_id="e")
    log: list[str] = []
    with patch("src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.settings") as s:
        s.sandbox_enabled = False
        out = await run_va_active_scan_phase(
            bundle,
            tenant_id_raw=None,
            scan_id_raw="job1",
            va_raw_log=log.append,
        )
    assert out is bundle
    assert any("sandbox_disabled" in x for x in log)


@pytest.mark.asyncio
async def test_va_active_scan_phase_skips_no_jobs() -> None:
    bundle = VulnerabilityAnalysisInputBundle(engagement_id="e")
    log: list[str] = []
    with patch("src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.settings") as s:
        s.sandbox_enabled = True
        s.va_active_scan_tool_timeout_sec = 30.0
        s.ffuf_va_wordlist_path = ""
        s.sqlmap_va_enabled = False
        with patch(
            "src.recon.vulnerability_analysis.active_scan.planner.collect_xsstrike_scan_jobs",
            return_value=[],
        ):
            out = await run_va_active_scan_phase(
                bundle,
                tenant_id_raw="t1",
                scan_id_raw="job1",
                va_raw_log=log.append,
            )
    assert any("no_targets" in x for x in log)


@pytest.mark.asyncio
async def test_va_active_scan_phase_runs_tools_mocked() -> None:
    bundle = VulnerabilityAnalysisInputBundle(engagement_id="e")
    log: list[str] = []
    jobs = [
        XsStrikeScanJob(
            url="https://example.com/search?q=1",
            post_data=None,
            source="params_inventory",
        )
    ]
    mock_result = {
        "exit_code": 0,
        "stdout": "ok",
        "stderr": "",
        "duration_ms": 1,
        "tool_id": "dalfox",
        "error_reason": "",
    }

    with patch("src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.settings") as s:
        s.sandbox_enabled = True
        s.va_active_scan_tool_timeout_sec = 30.0
        s.ffuf_va_wordlist_path = ""
        s.sqlmap_va_enabled = True
        with patch(
            "src.recon.vulnerability_analysis.active_scan.planner.collect_xsstrike_scan_jobs",
            return_value=jobs,
        ):
            with patch(
                "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.run_va_active_scan",
                new_callable=AsyncMock,
                return_value=mock_result,
            ) as m_run:
                with patch(
                    "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.sink_raw_text",
                ) as m_text:
                    with patch(
                        "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.sink_raw_json",
                    ) as m_json:
                        out = await run_va_active_scan_phase(
                            bundle,
                            tenant_id_raw="tenant-1",
                            scan_id_raw="job1",
                            va_raw_log=log.append,
                        )
    assert len(out.intel_findings) >= 4
    # One job × (dalfox, ffuf, sqlmap, nuclei, gobuster, wfuzz, commix)
    assert m_run.await_count >= 7
    assert m_text.call_count >= 21
    assert m_json.call_count >= 2
    assert any("va_active_scan_phase_done" in x for x in log)


@pytest.mark.asyncio
async def test_va_active_scan_phase_merges_nuclei_intel_mocked() -> None:
    bundle = VulnerabilityAnalysisInputBundle(engagement_id="e")
    log: list[str] = []
    jobs = [
        XsStrikeScanJob(
            url="https://example.com/search?q=1",
            post_data=None,
            source="params_inventory",
        )
    ]
    nuclei_jsonl = (
        '{"template-id":"probe-x","info":{"name":"P","severity":"medium"},'
        '"matched-at":"https://example.com/search?q=1"}\n'
    )
    base_result = {
        "exit_code": 0,
        "stdout": "ok",
        "stderr": "",
        "duration_ms": 1,
        "tool_id": "dalfox",
        "error_reason": "",
    }

    async def fake_run(**kwargs: object) -> dict:
        tool = str(kwargs.get("tool_name") or "")
        if tool == "nuclei":
            return {
                **base_result,
                "tool_id": "nuclei",
                "stdout": nuclei_jsonl,
            }
        return {**base_result, "tool_id": tool or "dalfox"}

    with patch("src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.settings") as s:
        s.sandbox_enabled = True
        s.va_active_scan_tool_timeout_sec = 30.0
        s.ffuf_va_wordlist_path = ""
        s.sqlmap_va_enabled = True
        with patch(
            "src.recon.vulnerability_analysis.active_scan.planner.collect_xsstrike_scan_jobs",
            return_value=jobs,
        ):
            with patch(
                "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.run_va_active_scan",
                new_callable=AsyncMock,
                side_effect=fake_run,
            ):
                with patch(
                    "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.sink_raw_text",
                ):
                    with patch(
                        "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.sink_raw_json",
                    ):
                        out = await run_va_active_scan_phase(
                            bundle,
                            tenant_id_raw="tenant-1",
                            scan_id_raw="job1",
                            va_raw_log=log.append,
                        )
    nuclei_rows = [x for x in out.intel_findings if x.get("source_tool") == "nuclei"]
    assert len(nuclei_rows) >= 1
    assert nuclei_rows[0].get("data", {}).get("template_id") == "probe-x"


@pytest.mark.asyncio
async def test_va_active_scan_phase_exec_os_error_keeps_stderr_artifact() -> None:
    bundle = VulnerabilityAnalysisInputBundle(engagement_id="e")
    log: list[str] = []
    jobs = [
        XsStrikeScanJob(
            url="https://example.com/a",
            post_data=None,
            source="params_inventory",
        )
    ]
    ok = {
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "duration_ms": 1,
        "tool_id": "dalfox",
        "error_reason": "",
    }
    busted = {
        "exit_code": -1,
        "stdout": "",
        "stderr": "",
        "duration_ms": 1,
        "tool_id": "gobuster",
        "error_reason": "exec_os_error",
    }

    async def fake_run(**kwargs: object) -> dict:
        tool = str(kwargs.get("tool_name") or "")
        if tool == "gobuster":
            return busted
        return {**ok, "tool_id": tool}

    stderr_texts: list[str] = []

    def capture_text(*args: object, **kwargs: object) -> None:
        at = kwargs.get("artifact_type")
        if isinstance(at, str) and at.endswith("_stderr"):
            t = kwargs.get("text")
            if isinstance(t, str):
                stderr_texts.append(t)

    with patch("src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.settings") as s:
        s.sandbox_enabled = True
        s.va_active_scan_tool_timeout_sec = 30.0
        s.ffuf_va_wordlist_path = ""
        s.sqlmap_va_enabled = True
        with patch(
            "src.recon.vulnerability_analysis.active_scan.planner.collect_xsstrike_scan_jobs",
            return_value=jobs,
        ):
            with patch(
                "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.run_va_active_scan",
                new_callable=AsyncMock,
                side_effect=fake_run,
            ):
                with patch(
                    "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.sink_raw_text",
                    side_effect=capture_text,
                ):
                    with patch(
                        "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.sink_raw_json",
                    ):
                        await run_va_active_scan_phase(
                            bundle,
                            tenant_id_raw="t",
                            scan_id_raw="job1",
                            va_raw_log=log.append,
                        )
    assert any("process_start_failed" in t for t in stderr_texts)
    assert any("exec_skip" in x and "gobuster" in x for x in log)


@pytest.mark.asyncio
async def test_pipeline_calls_active_scan_phase_after_xsstrike(tmp_path: Path) -> None:
    from src.recon.vulnerability_analysis.dependency_check import (
        STAGE1_REQUIRED_ARTIFACTS,
        STAGE2_REQUIRED_ARTIFACTS,
    )
    from src.recon.vulnerability_analysis.pipeline import execute_vulnerability_analysis_run

    for filename in STAGE1_REQUIRED_ARTIFACTS:
        (tmp_path / filename).write_text("{}" if filename.endswith(".json") else "a,b\n1,2")
    for filename in STAGE2_REQUIRED_ARTIFACTS:
        (tmp_path / filename).write_text("{}" if filename.endswith(".json") else "# TM")
    (tmp_path / "stage3_readiness.json").write_text(
        '{"status": "ready_for_stage3", "missing_evidence": [], "unknowns": [], '
        '"recommended_follow_up": [], "coverage_scores": {"route": 0.8, "input_surface": 0.7, '
        '"api_surface": 0.7, "content_anomaly": 0.5, "boundary_mapping": 0.6}}'
    )
    (tmp_path / "stage2_structured.json").write_text(
        '{"priority_hypotheses": [], "critical_assets": [], "trust_boundaries": [], "entry_points": []}'
    )
    (tmp_path / "ai_tm_critical_assets_normalized.json").write_text(
        '{"assets": [{"id": "ca1", "name": "API", "asset_type": "service", "description": "Main API"}]}'
    )
    (tmp_path / "ai_tm_threat_scenarios_normalized.json").write_text(
        '{"scenarios": [{"id": "ts1", "title": "Test", "related_assets": [], "description": "Scenario", '
        '"likelihood": 0.5, "impact": 0.5, "priority": "medium", "assumptions": [], "recommended_next_manual_checks": []}]}'
    )
    (tmp_path / "ai_tm_testing_roadmap_normalized.json").write_text(
        '{"items": [{"scenario_id": "ts1", "title": "Test", "priority": "medium", "recommended_actions": ["Verify"], "evidence_refs": []}]}'
    )

    mock_phase = AsyncMock(side_effect=lambda b, **kw: b)
    with patch(
        "src.recon.vulnerability_analysis.pipeline.run_va_active_scan_phase",
        mock_phase,
    ):
        await execute_vulnerability_analysis_run(
            engagement_id="e1",
            run_id="run1",
            job_id="job1",
            recon_dir=tmp_path,
            mcp_tools=[],
        )
    mock_phase.assert_awaited_once()
