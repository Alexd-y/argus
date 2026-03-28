"""XSS-007 — active scan bridge, planner jobs for query URLs, optional real-docker e2e.

Unit tests use mocks only. Set ``RUN_ALF_NU_E2E=1`` for optional integration (host Docker).
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, patch

import pytest

from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle

from src.orchestration.handlers import run_vuln_analysis
from src.orchestration.phases import VulnAnalysisOutput
from src.recon.vulnerability_analysis.active_scan.planner import build_va_active_scan_plan


def _alf_nu_bundle() -> VulnerabilityAnalysisInputBundle:
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


@pytest.mark.asyncio
async def test_run_vuln_analysis_calls_active_scan_when_sandbox_enabled() -> None:
    """Mock path: sandbox on + target → ``run_va_active_scan_phase`` invoked."""
    with (
        patch("src.orchestration.handlers.settings") as m_settings,
        patch(
            "src.orchestration.handlers._extract_url_params_and_forms",
            new_callable=AsyncMock,
            return_value=([], []),
        ),
        patch(
            "src.orchestration.handlers.run_va_active_scan_phase",
            new_callable=AsyncMock,
        ) as mock_phase,
        patch("src.orchestration.handlers.ai_vuln_analysis", new_callable=AsyncMock) as mock_ai,
    ):
        m_settings.sandbox_enabled = True
        mock_phase.return_value = VulnerabilityAnalysisInputBundle(
            engagement_id="x",
            target_id="t",
            entry_points=[],
            threat_scenarios=[],
            params_inventory=[],
            forms_inventory=[],
            intel_findings=[],
            live_hosts=[],
            tech_profile=[],
        )
        mock_ai.return_value = VulnAnalysisOutput(findings=[])

        await run_vuln_analysis(
            {"threats": []},
            [],
            target="https://example.com/x",
            tenant_id="00000000-0000-0000-0000-000000000001",
            scan_id="scan-1",
        )

        mock_phase.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_vuln_analysis_skips_active_scan_when_sandbox_disabled() -> None:
    with (
        patch("src.orchestration.handlers.settings") as m_settings,
        patch(
            "src.orchestration.handlers.run_va_active_scan_phase",
            new_callable=AsyncMock,
        ) as mock_phase,
        patch("src.orchestration.handlers.ai_vuln_analysis", new_callable=AsyncMock) as mock_ai,
    ):
        m_settings.sandbox_enabled = False
        mock_ai.return_value = VulnAnalysisOutput(findings=[])

        await run_vuln_analysis(
            {"threats": []},
            [],
            target="https://example.com/x",
        )

        mock_phase.assert_not_awaited()


def test_build_va_active_scan_plan_alf_nu_params_has_dalfox_or_xsstrike() -> None:
    plan = build_va_active_scan_plan(_alf_nu_bundle())
    tools = {s.tool_id for s in plan}
    assert "dalfox" in tools
    assert "xsstrike" in tools


@pytest.mark.integration
@pytest.mark.skipif(
    os.environ.get("RUN_ALF_NU_E2E", "").strip() != "1",
    reason="Set RUN_ALF_NU_E2E=1 to run real docker exec against local argus-sandbox",
)
def test_docker_socket_present_for_optional_e2e() -> None:
    """Document-only gate: real E2E requires Docker socket inside the test runner (usually skipped)."""
    assert os.path.exists("/var/run/docker.sock") or os.path.exists("//./pipe/docker_engine")
