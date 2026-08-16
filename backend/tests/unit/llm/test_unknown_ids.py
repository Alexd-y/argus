"""Unknown prompt/schema ID policy for the unified gateway."""

from __future__ import annotations

import pytest
from src.core.config import Settings, settings
from src.eval.rates import reset_eval_rates, snapshot_eval_rates
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
    LlmRequest,
    LlmResponseStatus,
)
from src.llm.unified_router import RoutingPolicy
from src.llm.unknown_ids import classify_unknown_ids


def _make_request(**overrides: object) -> LlmRequest:
    base: dict[str, object] = {
        "request_id": "req-unknown",
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
    return LlmRequest(**base)  # type: ignore[arg-type]


@pytest.fixture(autouse=True)
def enable_unified_gateway(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_unified_llm_gateway", True)
    reset_eval_rates()


@pytest.fixture
def isolated_registry() -> UnifiedRegistry:
    reset_unified_registry()
    reset_unified_llm_gateway()
    registry = UnifiedRegistry()
    registry.providers.register(
        ModelRecord(
            provider_id="local_qwythos",
            model="qwythos-9b-claude-mythos-5-1m",
            capabilities=ProviderCapability(
                json_schema=True, tool_calling=True, max_context=65536
            ),
            base_url="http://qwythos:8000/v1",
            adapter_kind="openai_compatible",
        )
    )
    registry.aliases.register(
        AliasEntry(
            alias="security_reasoner",
            provider_model_keys=["local_qwythos"],
            role="security",
        )
    )
    return registry


def test_gateway_defaults_on() -> None:
    assert Settings.model_fields["argus_unified_llm_gateway"].default is True
    assert settings.argus_unified_llm_gateway is True


def test_production_rejects_unknown_prompt_id() -> None:
    decision = classify_unknown_ids(
        _make_request(prompt_id="not_a_real_prompt"),
        known_schema_ids={"TestSchemaV1"},
    )
    assert decision.reject is True
    assert decision.unknown_ids == ("prompt_id:not_a_real_prompt",)


def test_lab_unknown_schema_uses_generated_artifact() -> None:
    decision = classify_unknown_ids(
        _make_request(
            execution_mode=ExecutionMode.LAB_UNRESTRICTED,
            response_schema_id="made_up_schema_v9",
        ),
        known_schema_ids={"TestSchemaV1"},
    )
    assert decision.reject is False
    assert decision.lab_generated_schema is True
    assert decision.resolved_schema_id == "lab_generated_artifact_v1"


@pytest.mark.asyncio
async def test_production_unknown_id_does_not_call_provider(
    isolated_registry: UnifiedRegistry,
) -> None:
    gateway = UnifiedLlmGateway(isolated_registry, RoutingPolicy(isolated_registry))
    called = {"n": 0}

    async def fake_invoke(route, req, system_prompt=""):  # type: ignore[no-untyped-def]
        called["n"] += 1
        return ProviderCallResult(text='{"answer":"nope"}', input_tokens=1, output_tokens=1)

    gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]
    response = await gateway.generate(
        _make_request(prompt_id="ghost_prompt", response_schema_id="ghost_schema")
    )
    assert called["n"] == 0
    assert response.status is LlmResponseStatus.UNKNOWN_ID
    assert "unknown_id" in response.routing_reason_codes
    rates = snapshot_eval_rates()
    assert rates.unknown_id_total >= 1
    assert rates.unknown_id_rate == 1.0


@pytest.mark.asyncio
async def test_lab_unknown_schema_still_calls_provider(
    isolated_registry: UnifiedRegistry,
) -> None:
    gateway = UnifiedLlmGateway(isolated_registry, RoutingPolicy(isolated_registry))

    async def fake_invoke(route, req, system_prompt=""):  # type: ignore[no-untyped-def]
        return ProviderCallResult(
            text='{"artifact":"raw","notes":"lab"}',
            input_tokens=4,
            output_tokens=2,
        )

    gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]
    response = await gateway.generate(
        _make_request(
            execution_mode=ExecutionMode.LAB_UNRESTRICTED,
            content_class=ContentClass.LAB_ARTIFACT,
            response_schema_id="unknown_lab_schema",
        )
    )
    assert response.status is LlmResponseStatus.OK
    assert "lab_generated_schema" in response.routing_reason_codes
    assert response.schema_id == "lab_generated_artifact_v1"
    assert response.result["artifact"] == "raw"


@pytest.mark.asyncio
async def test_ok_response_marks_uncited_facts_as_inference(
    isolated_registry: UnifiedRegistry,
) -> None:
    gateway = UnifiedLlmGateway(isolated_registry, RoutingPolicy(isolated_registry))

    async def fake_invoke(route, req, system_prompt=""):  # type: ignore[no-untyped-def]
        return ProviderCallResult(
            text="Confirmed SQL injection vulnerability in login.",
            input_tokens=8,
            output_tokens=6,
        )

    gateway._invoke_provider = fake_invoke  # type: ignore[method-assign]
    response = await gateway.generate(_make_request())
    assert response.status is LlmResponseStatus.OK
    assert response.inferred_claims
    assert "[INFERENCE]" in str(response.result.get("text", ""))
