"""Unit tests for facade → UnifiedLlmGateway bridge (CONT-002)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from src.core.config import settings
from src.llm.gateway import (
    ProviderCallError,
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
    LlmRequest,
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
    return registry


@pytest.fixture
def gateway_flag_on(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_unified_llm_gateway", True)


@pytest.fixture
def gateway_flag_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_unified_llm_gateway", False)


class TestFacadeGatewayFlagOn:
    @pytest.mark.asyncio
    async def test_flag_true_uses_gateway_path(self, gateway_flag_on: None) -> None:
        from src.llm.facade import call_llm_unified

        envelope = LlmResponseEnvelope(
            request_id="req-1",
            status=LlmResponseStatus.OK,
            result={"text": "gateway response"},
        )
        mock_gateway = AsyncMock()
        mock_gateway.generate = AsyncMock(return_value=envelope)

        with patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway):
            result = await call_llm_unified(
                "system",
                "user",
                task=LLMTask.ORCHESTRATION,
            )

        assert result == "gateway response"
        mock_gateway.generate.assert_awaited_once()
        request = mock_gateway.generate.await_args.args[0]
        assert request.task_type == LLMTask.ORCHESTRATION.value
        assert request.preferred_alias == "facade_orchestrator"

    @pytest.mark.asyncio
    async def test_primary_fail_tries_next_provider(
        self, gateway_flag_on: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from src.llm.facade import call_llm_unified

        registry = _make_registry()
        gateway = UnifiedLlmGateway(registry, RoutingPolicy(registry))
        calls: list[str] = []

        async def fake_invoke(route, req, system_prompt=""):
            calls.append(route.provider_id)
            if route.provider_id == "local_qwythos":
                raise ProviderCallError("qwythos down", "timeout")
            return ProviderCallResult(text="fallback text", input_tokens=8, output_tokens=4)

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]
        monkeypatch.setattr(
            "src.llm.facade.get_unified_llm_gateway",
            lambda: gateway,
        )

        result = await call_llm_unified(
            "system",
            "analyze",
            task=LLMTask.THREAT_MODELING,
        )

        assert result == "fallback text"
        assert calls == ["local_qwythos", "local_wrb"]

    @pytest.mark.asyncio
    async def test_schema_error_not_swallowed(self, gateway_flag_on: None) -> None:
        from src.llm.facade import call_llm_unified

        envelope = LlmResponseEnvelope(
            request_id="req-1",
            status=LlmResponseStatus.SCHEMA_ERROR,
            schema_id="TestSchemaV1",
            result={"raw_text": "not valid json"},
        )
        mock_gateway = AsyncMock()
        mock_gateway.generate = AsyncMock(return_value=envelope)

        with patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway):
            with pytest.raises(RuntimeError, match="schema validation failed"):
                await call_llm_unified(
                    "system",
                    "user",
                    task=LLMTask.VULN_ANALYSIS,
                    response_schema_id="TestSchemaV1",
                )

    @pytest.mark.asyncio
    async def test_provider_error_fail_closed_for_pentest(
        self, gateway_flag_on: None
    ) -> None:
        from src.llm.facade import call_llm_unified

        envelope = LlmResponseEnvelope(
            request_id="req-1",
            status=LlmResponseStatus.PROVIDER_ERROR,
            result={"error_code": "timeout"},
        )
        mock_gateway = AsyncMock()
        mock_gateway.generate = AsyncMock(return_value=envelope)

        with patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway):
            with pytest.raises(RuntimeError, match="provider error"):
                await call_llm_unified(
                    "system",
                    "user",
                    task=LLMTask.ORCHESTRATION,
                )

    @pytest.mark.asyncio
    async def test_provider_error_falls_through_for_report_task(
        self, gateway_flag_on: None
    ) -> None:
        from src.llm.facade import call_llm_unified

        envelope = LlmResponseEnvelope(
            request_id="req-1",
            status=LlmResponseStatus.PROVIDER_ERROR,
            result={"error_code": "timeout"},
        )
        mock_gateway = AsyncMock()
        mock_gateway.generate = AsyncMock(return_value=envelope)

        with patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway):
            with patch(
                "src.llm.facade._call_via_task_router",
                new_callable=AsyncMock,
                return_value="legacy report",
            ) as mock_legacy:
                result = await call_llm_unified(
                    "system",
                    "user",
                    task=LLMTask.REPORT_SECTION,
                )

        assert result == "legacy report"
        mock_legacy.assert_awaited_once()


class TestFacadeGatewayFlagOff:
    @pytest.mark.asyncio
    async def test_flag_false_uses_legacy_path(self, gateway_flag_off: None) -> None:
        from src.llm.facade import call_llm_unified

        mock_gateway = AsyncMock()
        with patch("src.llm.facade.get_unified_llm_gateway", return_value=mock_gateway):
            with patch(
                "src.llm.facade._call_via_task_router",
                new_callable=AsyncMock,
                return_value="legacy osint",
            ) as mock_legacy:
                result = await call_llm_unified(
                    "system",
                    "user",
                    task=LLMTask.PERPLEXITY_OSINT,
                )

        assert result == "legacy osint"
        mock_gateway.generate.assert_not_called()
        mock_legacy.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_flag_false_pentest_task_skips_gateway(
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
                    return_value="legacy wrb",
                ) as mock_wrb:
                    result = await call_llm_unified(
                        "system",
                        "user",
                        task=LLMTask.ORCHESTRATION,
                    )

            assert result == "legacy wrb"
            mock_gateway.generate.assert_not_called()
            mock_wrb.assert_awaited_once()
        finally:
            wrb._base_url = orig_url


class TestGatewayFailoverDirect:
    @pytest.mark.asyncio
    async def test_auth_error_on_primary_continues_to_next_provider(
        self, gateway_flag_on: None
    ) -> None:
        """Provider-specific auth errors must not abort the failover chain."""
        registry = _make_registry()
        gateway = UnifiedLlmGateway(registry, RoutingPolicy(registry))
        request = LlmRequest(
            request_id="req-auth",
            tenant_id="tenant-1",
            engagement_id="eng-1",
            phase="vuln_analysis",
            task_type="scan_plan",
            execution_mode=ExecutionMode.PRODUCTION,
            content_class=ContentClass.INTERNAL,
            preferred_alias="security_reasoner",
            user_prompt="test",
        )
        calls: list[str] = []

        async def fake_invoke(route, req, system_prompt=""):
            calls.append(route.provider_id)
            if route.provider_id == "local_qwythos":
                raise ProviderCallError("auth failed", "auth_error")
            return ProviderCallResult(text="ok from backup", input_tokens=5, output_tokens=2)

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]

        response = await gateway.generate(request)

        assert response.status == LlmResponseStatus.OK
        assert response.provider == "local_wrb"
        assert calls == ["local_qwythos", "local_wrb"]
        assert len(response.fallback_attempts) == 1
        assert response.fallback_attempts[0].error_code == "auth_error"
