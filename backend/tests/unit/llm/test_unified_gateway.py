"""Unit tests for unified LLM gateway (Stage B)."""

from __future__ import annotations

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
    LlmResponseStatus,
)
from src.llm.unified_router import RoutingPolicy


def _make_request(**overrides) -> LlmRequest:
    base = {
        "request_id": "req-1",
        "tenant_id": "tenant-1",
        "engagement_id": "eng-1",
        "phase": "vuln_analysis",
        "task_type": "scan_plan",
        "execution_mode": ExecutionMode.PRODUCTION,
        "content_class": ContentClass.INTERNAL,
        "preferred_alias": "security_reasoner",
        "user_prompt": "Analyze the target.",
        "prompt_id": "scan_planner_v2",
        "prompt_version": "2.0.0",
    }
    base.update(overrides)
    return LlmRequest(**base)


@pytest.fixture(autouse=True)
def enable_unified_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_unified_llm_gateway", True)


@pytest.fixture
def isolated_registry() -> UnifiedRegistry:
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
    registry.providers.register(
        ModelRecord(
            provider_id="cloud_deepseek",
            model="deepseek-chat",
            capabilities=ProviderCapability(
                json_schema=True,
                tool_calling=True,
                max_context=65536,
                local=False,
                content_classes=["public", "internal"],
            ),
            base_url="https://api.deepseek.com",
            env_key="DEEPSEEK_API_KEY",
            cloud=True,
            price_input_per_million_usd=0.14,
            price_output_per_million_usd=0.28,
            adapter_kind="cloud_adapter",
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
    return registry


class TestAliasResolution:
    def test_alias_resolves_to_real_provider_model(self, isolated_registry: UnifiedRegistry):
        policy = RoutingPolicy(isolated_registry)
        request = _make_request(preferred_alias="security_reasoner")
        chain = policy.build_chain(request)

        assert len(chain) >= 1
        first = chain[0]
        assert first.provider_id == "local_qwythos"
        assert first.model == "qwythos-9b-claude-mythos-5-1m"
        assert first.alias == "security_reasoner"

    def test_distinct_aliases_resolve_different_primary_providers(
        self, isolated_registry: UnifiedRegistry
    ):
        isolated_registry.aliases.register(
            AliasEntry(
                alias="facade_orchestrator",
                provider_model_keys=["local_qwythos", "local_wrb"],
                role="orchestrator",
            )
        )
        policy = RoutingPolicy(isolated_registry)

        chain_a = policy.build_chain(_make_request(preferred_alias="wrb_critic"))
        chain_b = policy.build_chain(_make_request(preferred_alias="facade_orchestrator"))

        assert chain_a[0].provider_id == "local_wrb"
        assert chain_a[0].model == "taico-ai/WhiteRabbitNeo-v3-7B"
        assert chain_b[0].provider_id == "local_qwythos"
        assert chain_b[0].model == "qwythos-9b-claude-mythos-5-1m"
        assert chain_a[0].provider_id != chain_b[0].provider_id
        assert chain_a[0].model != chain_b[0].model


class TestRoutingPolicy:
    def test_fallback_chain_has_multiple_providers(self, isolated_registry: UnifiedRegistry):
        policy = RoutingPolicy(isolated_registry)
        request = _make_request(preferred_alias="security_reasoner")
        chain = policy.build_chain(request)

        assert len(chain) > 1
        assert chain[0].provider_id == "local_qwythos"
        assert chain[1].provider_id == "local_wrb"

    def test_lab_offensive_task_not_refused(self, isolated_registry: UnifiedRegistry):
        policy = RoutingPolicy(isolated_registry)
        request = _make_request(
            execution_mode=ExecutionMode.LAB_UNRESTRICTED,
            task_type="exploit_generation",
            content_class=ContentClass.LAB_ARTIFACT,
            preferred_alias="unknown_alias",
        )
        chain = policy.build_chain(request)

        assert len(chain) > 0
        assert not any("refused" in code for route in chain for code in route.reason_codes)
        assert any(
            "lab_offensive" in code or "lab_no_refusal" in code
            for route in chain
            for code in route.reason_codes
        )


class TestUnifiedGateway:
    @pytest.mark.asyncio
    async def test_fallback_selects_next_provider_on_failure(self, isolated_registry: UnifiedRegistry):
        gateway = UnifiedLlmGateway(isolated_registry, RoutingPolicy(isolated_registry))
        request = _make_request(preferred_alias="security_reasoner")

        calls: list[str] = []

        async def fake_invoke(route, req, system_prompt=""):
            calls.append(route.provider_id)
            if route.provider_id == "local_qwythos":
                raise ProviderCallError("qwythos down", "timeout")
            return ProviderCallResult(
                text='{"answer":"ok"}',
                input_tokens=12,
                output_tokens=4,
            )

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]

        response = await gateway.generate(request)

        assert response.status == LlmResponseStatus.OK
        assert response.provider == "local_wrb"
        assert response.model == "taico-ai/WhiteRabbitNeo-v3-7B"
        assert len(response.fallback_attempts) == 1
        assert response.fallback_attempts[0].provider == "local_qwythos"
        assert calls == ["local_qwythos", "local_wrb"]

    @pytest.mark.asyncio
    async def test_schema_error_on_invalid_json_when_schema_required(
        self, isolated_registry: UnifiedRegistry
    ):
        gateway = UnifiedLlmGateway(isolated_registry, RoutingPolicy(isolated_registry))
        request = _make_request(
            preferred_alias="security_reasoner",
            response_schema_id="TestSchemaV1",
        )

        async def fake_invoke(route, req, system_prompt=""):
            return ProviderCallResult(text="not valid json at all", input_tokens=5, output_tokens=3)

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]

        response = await gateway.generate(request)

        assert response.status == LlmResponseStatus.SCHEMA_ERROR
        assert response.schema_id == "TestSchemaV1"
        assert "raw_text" in response.result

    @pytest.mark.asyncio
    async def test_usage_recorded(self, isolated_registry: UnifiedRegistry):
        gateway = UnifiedLlmGateway(isolated_registry, RoutingPolicy(isolated_registry))

        async def fake_invoke(route, req, system_prompt=""):
            return ProviderCallResult(
                text='{"answer":"tracked"}',
                input_tokens=100,
                output_tokens=25,
            )

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]

        response = await gateway.generate(
            _make_request(
                preferred_alias="security_reasoner",
                response_schema_id="TestSchemaV1",
            )
        )

        assert response.status == LlmResponseStatus.OK
        assert response.usage.input_tokens == 100
        assert response.usage.output_tokens == 25
        assert response.usage.latency_ms >= 0
        health = isolated_registry.health.get("local_qwythos")
        assert health.success_count >= 1

    @pytest.mark.asyncio
    async def test_alias_a_vs_b_produce_different_provider_model_in_envelope(
        self, isolated_registry: UnifiedRegistry
    ):
        isolated_registry.aliases.register(
            AliasEntry(
                alias="facade_orchestrator",
                provider_model_keys=["local_qwythos", "local_wrb"],
                role="orchestrator",
            )
        )
        gateway = UnifiedLlmGateway(isolated_registry, RoutingPolicy(isolated_registry))

        async def fake_invoke(route, req, system_prompt=""):
            return ProviderCallResult(
                text=f"ok from {route.provider_id}",
                input_tokens=3,
                output_tokens=2,
            )

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]

        env_a = await gateway.generate(_make_request(preferred_alias="wrb_critic"))
        env_b = await gateway.generate(_make_request(preferred_alias="facade_orchestrator"))

        assert env_a.status == LlmResponseStatus.OK
        assert env_b.status == LlmResponseStatus.OK
        assert env_a.alias == "wrb_critic"
        assert env_b.alias == "facade_orchestrator"
        assert env_a.provider == "local_wrb"
        assert env_a.model == "taico-ai/WhiteRabbitNeo-v3-7B"
        assert env_b.provider == "local_qwythos"
        assert env_b.model == "qwythos-9b-claude-mythos-5-1m"
        assert (env_a.provider, env_a.model) != (env_b.provider, env_b.model)

    @pytest.mark.asyncio
    async def test_lab_mode_injects_lab_unrestricted_system_prompt(
        self, isolated_registry: UnifiedRegistry
    ):
        from src.llm.prompts.prompts_pack import SYSTEM_LAB_UNRESTRICTED_V1

        gateway = UnifiedLlmGateway(isolated_registry, RoutingPolicy(isolated_registry))
        captured: dict[str, str] = {}

        async def fake_invoke(route, req, system_prompt=""):
            captured["system_prompt"] = system_prompt
            return ProviderCallResult(text="lab ok", input_tokens=1, output_tokens=1)

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]

        response = await gateway.generate(
            _make_request(
                preferred_alias="security_reasoner",
                execution_mode=ExecutionMode.LAB_UNRESTRICTED,
                task_type="exploit_generation",
                content_class=ContentClass.LAB_ARTIFACT,
            )
        )

        assert response.status == LlmResponseStatus.OK
        assert SYSTEM_LAB_UNRESTRICTED_V1 in captured["system_prompt"]
        assert "lab_unrestricted" in captured["system_prompt"]

    @pytest.mark.asyncio
    async def test_schema_error_status_is_typed_enum(
        self, isolated_registry: UnifiedRegistry
    ):
        gateway = UnifiedLlmGateway(isolated_registry, RoutingPolicy(isolated_registry))

        async def fake_invoke(route, req, system_prompt=""):
            return ProviderCallResult(text="definitely not json", input_tokens=2, output_tokens=1)

        gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]

        response = await gateway.generate(
            _make_request(
                preferred_alias="security_reasoner",
                response_schema_id="TestSchemaV1",
            )
        )

        assert response.status is LlmResponseStatus.SCHEMA_ERROR
        assert response.status == LlmResponseStatus.SCHEMA_ERROR
        assert response.status.value == "schema_error"
        assert isinstance(response.status, LlmResponseStatus)
