"""WIRE-002: facade execution_mode injection and LAB prompt attachment."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest
from src.core.config import settings
from src.execution_mode.runtime_context import (
    clear_runtime_execution_context,
    set_runtime_execution_mode,
)
from src.llm.gateway import (
    ProviderCallResult,
    UnifiedLlmGateway,
    reset_unified_llm_gateway,
)
from src.llm.prompts.prompts_pack import SYSTEM_LAB_UNRESTRICTED_V1
from src.llm.registry import (
    AliasEntry,
    ModelRecord,
    ProviderCapability,
    UnifiedRegistry,
    reset_unified_registry,
)
from src.llm.schemas import ExecutionMode, LlmResponseEnvelope, LlmResponseStatus
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
    registry.aliases.register(
        AliasEntry(
            alias="security_reasoner",
            provider_model_keys=["local_wrb"],
            role="security",
        )
    )
    registry.aliases.register(
        AliasEntry(
            alias="code_utility",
            provider_model_keys=["local_wrb"],
            role="code",
        )
    )
    return registry


@pytest.fixture(autouse=True)
def _clear_mode_context() -> None:
    clear_runtime_execution_context()
    yield
    clear_runtime_execution_context()


@pytest.fixture
def gateway_flag_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_unified_llm_gateway", True)


@pytest.fixture
def gateway_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_unified_llm_gateway", False)


class TestLabModeAttachesUnrestrictedPrompt:
    @pytest.mark.asyncio
    async def test_lab_mode_system_contains_lab_unrestricted_text(
        self, gateway_flag_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.llm.facade import call_llm_unified

        registry = _make_registry()
        gateway = UnifiedLlmGateway(registry, RoutingPolicy(registry))
        captured: dict[str, str] = {}

        async def fake_invoke(route, req, system_prompt=""):
            captured["system_prompt"] = system_prompt
            return ProviderCallResult(text="lab-ok", input_tokens=1, output_tokens=1)

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]
        monkeypatch.setattr("src.llm.facade.get_unified_llm_gateway", lambda: gateway)

        result = await call_llm_unified(
            "caller system",
            "plan exploit",
            task=LLMTask.EXPLOIT_GENERATION,
            execution_mode="lab_unrestricted",
        )

        assert result == "lab-ok"
        assert SYSTEM_LAB_UNRESTRICTED_V1 in captured["system_prompt"]
        assert "verified ARGUS lab_unrestricted execution lease" in captured["system_prompt"]


class TestFlagOffKeepsLegacyPath:
    @pytest.mark.asyncio
    async def test_flag_false_uses_legacy_path(self, gateway_flag_off: None) -> None:
        from src.llm.facade import call_llm_unified
        from src.llm.whiterabbitneo_adapter import get_whiterabbitneo_adapter

        wrb = get_whiterabbitneo_adapter()
        orig_url = wrb._base_url
        mock_gateway = AsyncMock()

        try:
            wrb._base_url = "http://wrb:8000/v1"
            with (
                patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway),
                patch(
                    "src.llm.facade._call_via_whiterabbitneo",
                    new_callable=AsyncMock,
                    return_value="legacy-wrb",
                ) as mock_wrb,
            ):
                result = await call_llm_unified(
                    "sys",
                    "user",
                    task=LLMTask.THREAT_MODELING,
                    execution_mode="lab_unrestricted",
                )

            assert result == "legacy-wrb"
            mock_gateway.generate.assert_not_called()
            mock_wrb.assert_awaited_once()
        finally:
            wrb._base_url = orig_url


class TestMissingModeDefaultsProduction:
    @pytest.mark.asyncio
    async def test_missing_mode_defaults_production(self, gateway_flag_on: None) -> None:
        from src.llm.facade import call_llm_unified

        envelope = LlmResponseEnvelope(
            request_id="req-prod",
            status=LlmResponseStatus.OK,
            result={"text": "prod"},
        )
        mock_gateway = AsyncMock()
        mock_gateway.generate = AsyncMock(return_value=envelope)

        with patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway):
            result = await call_llm_unified(
                "sys",
                "user",
                task=LLMTask.THREAT_MODELING,
            )

        assert result == "prod"
        request = mock_gateway.generate.await_args.args[0]
        assert request.execution_mode == ExecutionMode.PRODUCTION

    @pytest.mark.asyncio
    async def test_missing_mode_emits_structured_warning(
        self, gateway_flag_on: None, caplog: pytest.LogCaptureFixture
    ) -> None:
        from src.llm.facade import call_llm_unified

        envelope = LlmResponseEnvelope(
            request_id="req-warn",
            status=LlmResponseStatus.OK,
            result={"text": "ok"},
        )
        mock_gateway = AsyncMock()
        mock_gateway.generate = AsyncMock(return_value=envelope)

        with (
            patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway),
            caplog.at_level("WARNING", logger="src.llm.facade"),
        ):
            await call_llm_unified("sys", "user", task=LLMTask.VULN_ANALYSIS)

        assert any(
            rec.getMessage() == "llm_execution_mode_missing" for rec in caplog.records
        )

    @pytest.mark.asyncio
    async def test_scan_options_lab_mode_injected(self, gateway_flag_on: None) -> None:
        from src.llm.facade import call_llm_unified

        envelope = LlmResponseEnvelope(
            request_id="req-opts",
            status=LlmResponseStatus.OK,
            result={"text": "lab"},
        )
        mock_gateway = AsyncMock()
        mock_gateway.generate = AsyncMock(return_value=envelope)

        with patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway):
            await call_llm_unified(
                "sys",
                "user",
                task=LLMTask.ORCHESTRATION,
                scan_options={"execution_mode": "lab_unrestricted"},
            )

        request = mock_gateway.generate.await_args.args[0]
        assert request.execution_mode == ExecutionMode.LAB_UNRESTRICTED

    @pytest.mark.asyncio
    async def test_contextvar_lab_mode_injected(self, gateway_flag_on: None) -> None:
        from src.execution_mode.mode import ExecutionMode as DomainMode
        from src.llm.facade import call_llm_unified

        envelope = LlmResponseEnvelope(
            request_id="req-ctx",
            status=LlmResponseStatus.OK,
            result={"text": "lab"},
        )
        mock_gateway = AsyncMock()
        mock_gateway.generate = AsyncMock(return_value=envelope)

        set_runtime_execution_mode(DomainMode.LAB_UNRESTRICTED)
        with patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway):
            await call_llm_unified("sys", "user", task=LLMTask.EXPLOIT_GENERATION)

        request = mock_gateway.generate.await_args.args[0]
        assert request.execution_mode == ExecutionMode.LAB_UNRESTRICTED

    @pytest.mark.asyncio
    async def test_production_mode_omits_lab_prompt(
        self, gateway_flag_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.llm.facade import call_llm_unified

        registry = _make_registry()
        gateway = UnifiedLlmGateway(registry, RoutingPolicy(registry))
        captured: dict[str, str] = {}

        async def fake_invoke(route, req, system_prompt=""):
            captured["system_prompt"] = system_prompt
            return ProviderCallResult(text="prod-ok", input_tokens=1, output_tokens=1)

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]
        monkeypatch.setattr("src.llm.facade.get_unified_llm_gateway", lambda: gateway)

        await call_llm_unified(
            "caller system",
            "analyze",
            task=LLMTask.THREAT_MODELING,
            execution_mode=ExecutionMode.PRODUCTION,
        )

        assert SYSTEM_LAB_UNRESTRICTED_V1 not in captured["system_prompt"]
