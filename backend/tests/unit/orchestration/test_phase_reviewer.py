"""Tests for the config-gated reviewer/judge pass (Part B4)."""

from unittest.mock import AsyncMock, patch

import pytest

from src.llm import phase_routing
from src.orchestration.handlers import _maybe_run_phase_reviewer
from src.orchestration.phases import VulnAnalysisOutput


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    phase_routing.reset_cache()
    yield
    phase_routing.reset_cache()


@pytest.mark.asyncio
async def test_reviewer_noop_when_disabled(monkeypatch):
    monkeypatch.delenv("ARGUS_PHASE_ROUTING_ENABLED", raising=False)
    out = VulnAnalysisOutput(findings=[{"finding_id": "F1", "title": "x"}])
    await _maybe_run_phase_reviewer("vuln_analysis", out, scan_id="s1")
    assert "phase_review" not in (out.active_injection_coverage or {})


@pytest.mark.asyncio
async def test_reviewer_runs_and_annotates_when_enabled(monkeypatch):
    monkeypatch.setenv("ARGUS_PHASE_ROUTING_ENABLED", "true")
    phase_routing.reset_cache()
    out = VulnAnalysisOutput(findings=[{"finding_id": "F1", "title": "x"}])

    fake = AsyncMock(
        return_value='{"findings_reviewed": 1, "critiques": [], "blind_spots": ["b"], "overall_assessment": "ok"}'
    )
    with patch("src.llm.facade.call_llm_unified", fake):
        await _maybe_run_phase_reviewer("vuln_analysis", out, scan_id="s1")

    review = (out.active_injection_coverage or {}).get("phase_review")
    assert review is not None
    assert review["reviewer_alias"] == "argus-judge"
    assert fake.await_count == 1
