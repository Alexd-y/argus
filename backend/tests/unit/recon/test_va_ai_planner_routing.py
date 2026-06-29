"""Tests that the VA AI active-scan planner routes through the unified LLM facade
(Part A: point 4) and falls back to an empty plan (deterministic base) on failure.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

import src.recon.vulnerability_analysis.active_scan_planner as planner
from src.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle


def _enable(monkeypatch):
    monkeypatch.setattr(planner.settings, "va_ai_plan_enabled", True, raising=False)
    monkeypatch.setattr(planner, "has_any_llm_key", lambda: True)
    monkeypatch.setattr(planner, "sink_raw_json", lambda **kwargs: None)


@pytest.mark.asyncio
async def test_planner_routes_through_unified_facade(monkeypatch):
    _enable(monkeypatch)
    mock_unified = AsyncMock(return_value='[{"tool": "nuclei", "args": ["-u", "https://t.example"]}]')
    monkeypatch.setattr("src.llm.facade.call_llm_unified", mock_unified)

    bundle = VulnerabilityAnalysisInputBundle(engagement_id="e1")
    rows = await planner.plan_active_scan_with_ai(bundle, tenant_id=None, scan_id="s1")

    assert mock_unified.await_count == 1
    # routed via the unified facade with a planner task
    _, kwargs = mock_unified.call_args
    assert kwargs.get("task") is not None
    assert rows == [{"tool": "nuclei", "args": ["-u", "https://t.example"]}]


@pytest.mark.asyncio
async def test_planner_falls_back_to_empty_on_llm_error(monkeypatch):
    _enable(monkeypatch)
    monkeypatch.setattr(
        "src.llm.facade.call_llm_unified",
        AsyncMock(side_effect=RuntimeError("provider down")),
    )

    bundle = VulnerabilityAnalysisInputBundle(engagement_id="e1")
    rows = await planner.plan_active_scan_with_ai(bundle, tenant_id=None, scan_id="s1")

    # Deterministic base plan is preserved by callers; AI rows are empty.
    assert rows == []


@pytest.mark.asyncio
async def test_planner_skips_when_disabled(monkeypatch):
    monkeypatch.setattr(planner.settings, "va_ai_plan_enabled", False, raising=False)
    mock_unified = AsyncMock(return_value="[]")
    monkeypatch.setattr("src.llm.facade.call_llm_unified", mock_unified)

    bundle = VulnerabilityAnalysisInputBundle(engagement_id="e1")
    rows = await planner.plan_active_scan_with_ai(bundle, tenant_id=None, scan_id="s1")

    assert rows == []
    assert mock_unified.await_count == 0
