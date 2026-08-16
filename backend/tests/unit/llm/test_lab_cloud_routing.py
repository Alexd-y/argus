"""LAB cloud routing gate and default Qwythos-first aliases."""

from __future__ import annotations

import pytest
from src.llm.registry import (
    AliasEntry,
    ModelRecord,
    ProviderCapability,
    UnifiedRegistry,
    reset_unified_registry,
)
from src.llm.schemas import ContentClass, ExecutionMode, LlmRequest
from src.llm.unified_router import RoutingPolicy


def _request(**overrides: object) -> LlmRequest:
    base: dict[str, object] = {
        "request_id": "req-1",
        "tenant_id": "t-1",
        "engagement_id": "e-1",
        "phase": "vuln_analysis",
        "task_type": "threat_modeling",
        "execution_mode": ExecutionMode.LAB_UNRESTRICTED,
        "content_class": ContentClass.LAB_ARTIFACT,
        "preferred_alias": "report_writer",
        "user_prompt": "x",
        "lab_cloud_allowed": False,
    }
    base.update(overrides)
    return LlmRequest(**base)  # type: ignore[arg-type]


@pytest.fixture
def registry(monkeypatch: pytest.MonkeyPatch) -> UnifiedRegistry:
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-test")
    reset_unified_registry()
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
    registry.providers.register(
        ModelRecord(
            provider_id="cloud_deepseek",
            model="deepseek-chat",
            capabilities=ProviderCapability(
                json_schema=True,
                tool_calling=True,
                max_context=65536,
                local=False,
                content_classes=["public", "internal", "lab_artifact"],
            ),
            base_url="https://api.deepseek.com",
            env_key="DEEPSEEK_API_KEY",
            cloud=True,
            adapter_kind="cloud_adapter",
        )
    )
    registry.aliases.register(
        AliasEntry(
            alias="report_writer",
            provider_model_keys=["local_qwythos", "cloud_deepseek"],
            role="report",
        )
    )
    return registry


def test_lab_skips_cloud_when_not_allowed(registry: UnifiedRegistry) -> None:
    chain = RoutingPolicy(registry).build_chain(_request(lab_cloud_allowed=False))
    assert [route.provider_id for route in chain] == ["local_qwythos"]
    assert all(not route.cloud for route in chain)


def test_lab_allows_cloud_when_flag_set(registry: UnifiedRegistry) -> None:
    chain = RoutingPolicy(registry).build_chain(_request(lab_cloud_allowed=True))
    assert [route.provider_id for route in chain] == ["local_qwythos", "cloud_deepseek"]
    assert chain[1].cloud is True


def test_lab_offensive_not_refused_without_cloud(registry: UnifiedRegistry) -> None:
    chain = RoutingPolicy(registry).build_chain(
        _request(
            preferred_alias="report_writer",
            task_type="exploit_generation",
            lab_cloud_allowed=False,
        )
    )
    assert chain
    assert chain[0].provider_id == "local_qwythos"


def test_default_security_reasoner_prefers_qwythos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QWYTHOS_URL", "http://qwythos:8000/v1")
    monkeypatch.setenv("WHITERABBITNEO_URL", "http://wrb:8000/v1")
    reset_unified_registry()
    registry = UnifiedRegistry()
    entry = registry.aliases.resolve("security_reasoner")
    assert entry is not None
    assert entry.provider_model_keys[0] == "local_qwythos"
    critic = registry.aliases.resolve("wrb_critic")
    assert critic is not None
    assert critic.provider_model_keys[0] == "local_wrb"
    chain = RoutingPolicy(registry).build_chain(
        _request(
            preferred_alias="security_reasoner",
            task_type="threat_modeling",
            lab_cloud_allowed=False,
        )
    )
    assert chain[0].provider_id == "local_qwythos"
