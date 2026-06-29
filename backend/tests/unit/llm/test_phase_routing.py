"""Tests for phase-aware routing (Part B1/B2): config resolution + facade execution."""

from unittest.mock import AsyncMock, patch

import pytest

from src.llm import phase_routing
from src.llm.task_router import LLMTask


@pytest.fixture(autouse=True)
def _reset_routes():
    phase_routing.reset_cache()
    yield
    phase_routing.reset_cache()


class TestPhaseRoutingConfig:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("ARGUS_PHASE_ROUTING_ENABLED", raising=False)
        assert phase_routing.get_phase_route("vuln_analysis") is None

    def test_enabled_resolves_known_phase(self, monkeypatch):
        monkeypatch.setenv("ARGUS_PHASE_ROUTING_ENABLED", "true")
        route = phase_routing.get_phase_route("exploitation")
        assert route is not None
        assert route.mode == "wrb"
        assert route.fallback == "cloud"

    def test_unmapped_phase_returns_none_when_enabled(self, monkeypatch):
        monkeypatch.setenv("ARGUS_PHASE_ROUTING_ENABLED", "true")
        assert phase_routing.get_phase_route("payload_fallback") is None


@pytest.mark.asyncio
class TestFacadePhaseRouteExecution:
    async def test_cloud_primary_used_when_route_cloud(self, monkeypatch):
        monkeypatch.setenv("ARGUS_PHASE_ROUTING_ENABLED", "true")
        phase_routing.reset_cache()
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
        from src.llm import facade

        with patch.object(facade, "_call_via_task_router", new_callable=AsyncMock) as cloud, \
             patch.object(facade, "_call_via_whiterabbitneo", new_callable=AsyncMock) as wrb_call:
            cloud.return_value = "cloud-out"
            out = await facade.call_llm_unified(
                "sys", "usr", task=LLMTask.THREAT_MODELING, phase="threat_modeling"
            )
        assert out == "cloud-out"
        cloud.assert_awaited_once()
        wrb_call.assert_not_called()

    async def test_cloud_primary_falls_back_to_wrb(self, monkeypatch):
        monkeypatch.setenv("ARGUS_PHASE_ROUTING_ENABLED", "true")
        phase_routing.reset_cache()
        monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
        from src.llm import facade

        wrb = facade._get_wrb_adapter()
        orig = wrb._base_url
        wrb._base_url = "http://wrb:8000/v1"
        try:
            with patch.object(facade, "_call_via_task_router", new_callable=AsyncMock) as cloud, \
                 patch.object(facade, "_call_via_whiterabbitneo", new_callable=AsyncMock) as wrb_call:
                cloud.side_effect = RuntimeError("cloud down")
                wrb_call.return_value = "wrb-fallback"
                out = await facade.call_llm_unified(
                    "sys", "usr", task=LLMTask.THREAT_MODELING, phase="threat_modeling"
                )
            assert out == "wrb-fallback"
            cloud.assert_awaited_once()
            wrb_call.assert_awaited_once()
        finally:
            wrb._base_url = orig
