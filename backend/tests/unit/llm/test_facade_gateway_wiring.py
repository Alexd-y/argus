"""Facade ↔ UnifiedLlmGateway alias / execution-mode wiring (task-02)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.core.config import settings
from src.llm.gateway import (
    ProviderCallResult,
    UnifiedLlmGateway,
    reset_unified_llm_gateway,
)
from src.llm.registry import (
    AliasEntry,
    ModelRecord,
    ProviderCapability,
    UnifiedRegistry,
    reset_unified_registry,
)
from src.llm.schemas import (
    ContentClass,
    ExecutionMode,
    LlmResponseEnvelope,
    LlmResponseStatus,
)
from src.llm.task_router import LLMTask
from src.llm.unified_router import RoutingPolicy


def _make_registry() -> UnifiedRegistry:
    reset_unified_registry()
    reset_unified_llm_gateway()
    registry = UnifiedRegistry()
    registry.providers.register(
        ModelRecord(
            provider_id="local_wrb",
            model="taico-ai/WhiteRabbitNeo-v3-7B",
            capabilities=ProviderCapability(json_schema=True, tool_calling=True, max_context=32768),
            base_url="http://wrb:8000/v1",
            adapter_kind="whiterabbitneo",
        )
    )
    registry.providers.register(
        ModelRecord(
            provider_id="local_qwythos",
            model="qwythos-9b-claude-mythos-5-1m",
            capabilities=ProviderCapability(json_schema=True, tool_calling=True, max_context=65536),
            base_url="http://qwythos:8000/v1",
            adapter_kind="openai_compatible",
        )
    )
    registry.aliases.register(
        AliasEntry(
            alias="security_reasoner",
            provider_model_keys=["local_qwythos", "local_wrb"],
            role="security",
        )
    )
    registry.aliases.register(
        AliasEntry(
            alias="wrb_critic",
            provider_model_keys=["local_wrb", "local_qwythos"],
            role="exploit",
        )
    )
    registry.aliases.register(
        AliasEntry(
            alias="facade_orchestrator",
            provider_model_keys=["local_qwythos", "local_wrb"],
            role="orchestrator",
        )
    )
    registry.aliases.register(
        AliasEntry(
            alias="code_utility",
            provider_model_keys=["local_qwythos"],
            role="code",
        )
    )
    return registry


@pytest.fixture
def gateway_flag_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_unified_llm_gateway", True)


@pytest.fixture
def gateway_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_unified_llm_gateway", False)


class TestTaskAliasMapping:
    def test_orchestration_maps_to_facade_orchestrator(self) -> None:
        from src.llm.facade import _task_to_preferred_alias

        assert _task_to_preferred_alias(LLMTask.ORCHESTRATION) == "facade_orchestrator"

    def test_threat_modeling_maps_to_security_reasoner(self) -> None:
        from src.llm.facade import _task_to_preferred_alias

        assert _task_to_preferred_alias(LLMTask.THREAT_MODELING) == "security_reasoner"

    def test_exploit_generation_maps_to_wrb_critic(self) -> None:
        from src.llm.facade import _task_to_preferred_alias

        assert _task_to_preferred_alias(LLMTask.EXPLOIT_GENERATION) == "wrb_critic"


class TestFacadeAliasChangesProvider:
    @pytest.mark.asyncio
    async def test_different_tasks_select_different_providers(
        self, gateway_flag_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.llm.facade import call_llm_unified

        registry = _make_registry()
        gateway = UnifiedLlmGateway(registry, RoutingPolicy(registry))
        seen: list[tuple[str, str, str]] = []

        async def fake_invoke(route, req, system_prompt=""):
            seen.append((route.alias, route.provider_id, route.model))
            return ProviderCallResult(text=f"from-{route.provider_id}", input_tokens=1, output_tokens=1)

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]
        monkeypatch.setattr("src.llm.facade.get_unified_llm_gateway", lambda: gateway)

        text_a = await call_llm_unified(
            "sys", "user", task=LLMTask.ORCHESTRATION, phase="recon"
        )
        text_b = await call_llm_unified(
            "sys", "user", task=LLMTask.EXPLOIT_GENERATION, phase="exploitation"
        )

        assert text_a == "from-local_qwythos"
        assert text_b == "from-local_wrb"
        assert seen[0][0] == "facade_orchestrator"
        assert seen[1][0] == "wrb_critic"
        assert (seen[0][1], seen[0][2]) != (seen[1][1], seen[1][2])

    @pytest.mark.asyncio
    async def test_explicit_preferred_alias_overrides_task_map(
        self, gateway_flag_on: None
    ) -> None:
        from src.llm.facade import call_llm_unified

        envelope = LlmResponseEnvelope(
            request_id="req-1",
            status=LlmResponseStatus.OK,
            provider="local_qwythos",
            model="qwythos-9b-claude-mythos-5-1m",
            alias="facade_orchestrator",
            result={"text": "overridden"},
        )
        mock_gateway = AsyncMock()
        mock_gateway.generate = AsyncMock(return_value=envelope)

        with patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway):
            result = await call_llm_unified(
                "sys",
                "user",
                task=LLMTask.THREAT_MODELING,
                preferred_alias="facade_orchestrator",
            )

        assert result == "overridden"
        request = mock_gateway.generate.await_args.args[0]
        assert request.preferred_alias == "facade_orchestrator"


class TestFacadeLabModeWiring:
    @pytest.mark.asyncio
    async def test_lab_execution_mode_forwarded_to_gateway(
        self, gateway_flag_on: None
    ) -> None:
        from src.llm.facade import call_llm_unified

        envelope = LlmResponseEnvelope(
            request_id="req-lab",
            status=LlmResponseStatus.OK,
            result={"text": "lab"},
        )
        mock_gateway = AsyncMock()
        mock_gateway.generate = AsyncMock(return_value=envelope)

        with patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway):
            await call_llm_unified(
                "sys",
                "user",
                task=LLMTask.EXPLOIT_GENERATION,
                execution_mode="lab_unrestricted",
            )

        request = mock_gateway.generate.await_args.args[0]
        assert request.execution_mode == ExecutionMode.LAB_UNRESTRICTED
        assert request.content_class == ContentClass.LAB_ARTIFACT

    @pytest.mark.asyncio
    async def test_lab_mode_uses_lab_system_prompt_via_gateway(
        self, gateway_flag_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.llm.facade import call_llm_unified
        from src.llm.prompts.prompts_pack import SYSTEM_LAB_UNRESTRICTED_V1

        registry = _make_registry()
        gateway = UnifiedLlmGateway(registry, RoutingPolicy(registry))
        captured: dict[str, str] = {}

        async def fake_invoke(route, req, system_prompt=""):
            captured["system_prompt"] = system_prompt
            return ProviderCallResult(text="lab-payload", input_tokens=1, output_tokens=1)

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]
        monkeypatch.setattr("src.llm.facade.get_unified_llm_gateway", lambda: gateway)

        result = await call_llm_unified(
            "caller system",
            "generate exploit",
            task=LLMTask.EXPLOIT_GENERATION,
            execution_mode=ExecutionMode.LAB_UNRESTRICTED,
        )

        assert result == "lab-payload"
        assert SYSTEM_LAB_UNRESTRICTED_V1 in captured["system_prompt"]


class TestFacadeFlagOffUnchanged:
    @pytest.mark.asyncio
    async def test_flag_off_skips_gateway_for_analysis_task(
        self, gateway_flag_off: None
    ) -> None:
        from src.llm.facade import call_llm_unified
        from src.llm.whiterabbitneo_adapter import get_whiterabbitneo_adapter

        wrb = get_whiterabbitneo_adapter()
        orig_url = wrb._base_url
        mock_gateway = AsyncMock()

        try:
            wrb._base_url = "http://wrb:8000/v1"
            with patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway):
                with patch(
                    "src.llm.facade._call_via_whiterabbitneo",
                    new_callable=AsyncMock,
                    return_value="legacy",
                ) as mock_wrb:
                    result = await call_llm_unified(
                        "sys",
                        "user",
                        task=LLMTask.THREAT_MODELING,
                        execution_mode="lab_unrestricted",
                    )

            assert result == "legacy"
            mock_gateway.generate.assert_not_called()
            mock_wrb.assert_awaited_once()
        finally:
            wrb._base_url = orig_url
