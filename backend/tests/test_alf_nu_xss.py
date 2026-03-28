"""XSS-004 — minimum dalfox/xsstrike/ffuf plan rows for query URLs (alf.nu-style bundles)."""

from __future__ import annotations

import os

import pytest

from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle

from src.recon.vulnerability_analysis.active_scan.planner import (
    build_va_active_scan_plan,
    ensure_minimum_xss_surface_plan,
    renumber_active_scan_plan_indices,
)


def _alf_nu_bundle() -> VulnerabilityAnalysisInputBundle:
    """Same shape as handlers use for a query URL (params + scoped live host)."""
    return VulnerabilityAnalysisInputBundle(
        engagement_id="e-alf",
        target_id="alf-nu",
        entry_points=[],
        threat_scenarios=[],
        params_inventory=[
            {"url": "https://alf.nu/alert1", "param": "world", "method": "GET"},
            {"url": "https://alf.nu/alert1", "param": "level", "method": "GET"},
        ],
        forms_inventory=[],
        intel_findings=[],
        live_hosts=[{"host": "https://alf.nu/alert1?world=alert&level=alert0"}],
        tech_profile=[],
    )


def _finalize_va_plan(bundle: VulnerabilityAnalysisInputBundle) -> list:
    """Match production ordering: deterministic job plan + minimum XSS surface (phase applies after AI)."""
    base = build_va_active_scan_plan(bundle)
    return renumber_active_scan_plan_indices(ensure_minimum_xss_surface_plan(bundle, base))


@pytest.mark.integration
def test_alf_nu_bundle_minimum_xss_trio_in_final_plan() -> None:
    plan = _finalize_va_plan(_alf_nu_bundle())
    tools = {s.tool_id for s in plan}
    assert {"dalfox", "xsstrike", "ffuf"}.issubset(tools)
    min_rows = [s for s in plan if s.job_source == "minimum_xss_query_surface"]
    assert {s.tool_id for s in min_rows} == {"dalfox", "xsstrike", "ffuf"}
    assert any("world=" in s.url and "level=" in s.url for s in min_rows)


@pytest.mark.integration
def test_minimum_xss_when_xsstrike_jobs_empty_max_jobs_zero() -> None:
    """collect_xsstrike_scan_jobs yields nothing (max_jobs=0), query surface still schedules trio."""
    b = _alf_nu_bundle()
    core = build_va_active_scan_plan(b, max_jobs=0)
    assert core == []
    plan = renumber_active_scan_plan_indices(ensure_minimum_xss_surface_plan(b, core))
    assert {s.tool_id for s in plan} == {"dalfox", "xsstrike", "ffuf"}


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("RUN_ALF_NU_API_E2E", "").strip() != "1",
    reason="Set RUN_ALF_NU_API_E2E=1 to attempt live fetch (optional; network-dependent)",
)
@pytest.mark.asyncio
async def test_optional_live_alf_nu_head() -> None:
    import httpx

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        r = await client.get("https://alf.nu/alert1", follow_redirects=True)
    assert r.status_code < 500
