"""Unified model/provider/alias registry — single source of truth (master prompt §6)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from src.llm.schemas import CircuitState, ContentClass


@dataclass
class ProviderCapability:
    json_schema: bool = False
    tool_calling: bool = False
    streaming: bool = False
    max_context: int = 32768
    local: bool = True
    content_classes: list[str] = field(default_factory=lambda: ["*"])

    def supports(self, capability: str) -> bool:
        if capability == "json_schema":
            return self.json_schema
        if capability == "tool_calling":
            return self.tool_calling
        if capability == "streaming":
            return self.streaming
        return False

    def allows_content_class(self, content_class: ContentClass | str) -> bool:
        if "*" in self.content_classes:
            return True
        cc = content_class if isinstance(content_class, str) else content_class.value
        return cc in self.content_classes


@dataclass
class ProviderHealth:
    circuit: CircuitState = CircuitState.CLOSED
    success_rate_5m: float = 1.0
    p95_ms: int = 0
    last_error_code: str | None = None
    success_count: int = 0
    failure_count: int = 0

    def record_success(self, latency_ms: int) -> None:
        self.success_count += 1
        self.p95_ms = max(self.p95_ms, latency_ms)
        total = self.success_count + self.failure_count
        self.success_rate_5m = self.success_count / total if total else 1.0
        if self.circuit == CircuitState.HALF_OPEN:
            self.circuit = CircuitState.CLOSED
        self.last_error_code = None

    def record_failure(self, error_code: str) -> None:
        self.failure_count += 1
        total = self.success_count + self.failure_count
        self.success_rate_5m = self.success_count / total if total else 0.0
        self.last_error_code = error_code
        if self.failure_count >= 3 and self.circuit == CircuitState.CLOSED or self.circuit == CircuitState.HALF_OPEN:
            self.circuit = CircuitState.OPEN

    def is_available(self) -> bool:
        return self.circuit in (CircuitState.CLOSED, CircuitState.HALF_OPEN)


@dataclass
class ModelRecord:
    provider_id: str
    model: str
    capabilities: ProviderCapability
    base_url: str = ""
    env_key: str = ""
    cloud: bool = False
    price_input_per_million_usd: float = 0.0
    price_output_per_million_usd: float = 0.0
    adapter_kind: str = "openai_compatible"

    @property
    def is_configured(self) -> bool:
        if self.adapter_kind == "whiterabbitneo":
            return bool(self.base_url)
        if self.cloud:
            return bool(os.environ.get(self.env_key, "").strip())
        return bool(self.base_url)


@dataclass
class AliasEntry:
    alias: str
    provider_model_keys: list[str]
    role: str = ""


class ProviderRegistry:
    def __init__(self) -> None:
        self._providers: dict[str, ModelRecord] = {}
        self._load_defaults()

    def _load_defaults(self) -> None:
        wrb_url = os.environ.get("WHITERABBITNEO_URL", "").strip()
        qwythos_url = os.environ.get("QWYTHOS_URL", "").strip()
        gemma_url = os.environ.get("GEMMA_LOCAL_URL", "").strip()
        qwen_url = os.environ.get("QWEN_LOCAL_URL", "").strip()

        entries: list[ModelRecord] = [
            ModelRecord(
                provider_id="local_qwythos",
                model="qwythos-9b-claude-mythos-5-1m",
                capabilities=ProviderCapability(
                    json_schema=True,
                    tool_calling=True,
                    streaming=True,
                    max_context=65536,
                    local=True,
                ),
                base_url=qwythos_url,
                cloud=False,
                adapter_kind="openai_compatible",
            ),
            ModelRecord(
                provider_id="local_wrb",
                model="taico-ai/WhiteRabbitNeo-v3-7B",
                capabilities=ProviderCapability(
                    json_schema=True,
                    tool_calling=True,
                    streaming=True,
                    max_context=32768,
                    local=True,
                ),
                base_url=wrb_url,
                env_key="WHITERABBITNEO_API_KEY",
                cloud=False,
                adapter_kind="whiterabbitneo",
            ),
            ModelRecord(
                provider_id="local_gemma_fast",
                model="gemma-2-2b-it",
                capabilities=ProviderCapability(
                    json_schema=True,
                    tool_calling=False,
                    streaming=True,
                    max_context=8192,
                    local=True,
                ),
                base_url=gemma_url,
                cloud=False,
                adapter_kind="openai_compatible",
            ),
            ModelRecord(
                provider_id="local_qwen_fast",
                model="qwen3-4b-instruct",
                capabilities=ProviderCapability(
                    json_schema=True,
                    tool_calling=False,
                    streaming=True,
                    max_context=32768,
                    local=True,
                ),
                base_url=qwen_url,
                cloud=False,
                adapter_kind="openai_compatible",
            ),
            ModelRecord(
                provider_id="cloud_deepseek",
                model="deepseek-chat",
                capabilities=ProviderCapability(
                    json_schema=True,
                    tool_calling=True,
                    streaming=True,
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
            ),
            ModelRecord(
                provider_id="cloud_openai",
                model="gpt-4o-mini",
                capabilities=ProviderCapability(
                    json_schema=True,
                    tool_calling=True,
                    streaming=True,
                    max_context=128000,
                    local=False,
                    content_classes=["public", "internal"],
                ),
                base_url="https://api.openai.com",
                env_key="OPENAI_API_KEY",
                cloud=True,
                price_input_per_million_usd=0.15,
                price_output_per_million_usd=0.60,
                adapter_kind="cloud_adapter",
            ),
            ModelRecord(
                provider_id="cloud_openrouter",
                model="openai/gpt-4o-mini",
                capabilities=ProviderCapability(
                    json_schema=True,
                    tool_calling=True,
                    streaming=True,
                    max_context=128000,
                    local=False,
                    content_classes=["public", "internal"],
                ),
                base_url="https://openrouter.ai/api",
                env_key="OPENROUTER_API_KEY",
                cloud=True,
                price_input_per_million_usd=0.15,
                price_output_per_million_usd=0.60,
                adapter_kind="cloud_adapter",
            ),
            ModelRecord(
                provider_id="cloud_perplexity",
                model="sonar",
                capabilities=ProviderCapability(
                    json_schema=False,
                    tool_calling=False,
                    streaming=True,
                    max_context=32768,
                    local=False,
                    content_classes=["public"],
                ),
                base_url="https://api.perplexity.ai",
                env_key="PERPLEXITY_API_KEY",
                cloud=True,
                price_input_per_million_usd=1.0,
                price_output_per_million_usd=1.0,
                adapter_kind="cloud_adapter",
            ),
        ]
        for entry in entries:
            self._providers[entry.provider_id] = entry

    def get(self, provider_id: str) -> ModelRecord | None:
        return self._providers.get(provider_id)

    def list_all(self) -> list[ModelRecord]:
        return list(self._providers.values())

    def register(self, record: ModelRecord) -> None:
        self._providers[record.provider_id] = record


class ModelRegistry:
    """Index of models by provider_id — mirrors ProviderRegistry for §6 naming."""

    def __init__(self, provider_registry: ProviderRegistry) -> None:
        self._provider_registry = provider_registry

    def get(self, provider_id: str) -> ModelRecord | None:
        return self._provider_registry.get(provider_id)

    def list_all(self) -> list[ModelRecord]:
        return self._provider_registry.list_all()


class AliasRegistry:
    def __init__(self, provider_registry: ProviderRegistry) -> None:
        self._provider_registry = provider_registry
        self._aliases: dict[str, AliasEntry] = {}
        self._load_defaults()

    def _load_defaults(self) -> None:
        defaults: list[dict[str, Any]] = [
            {
                "alias": "security_reasoner",
                "role": "security",
                "provider_model_keys": ["local_qwythos", "local_wrb"],
            },
            {
                "alias": "facade_orchestrator",
                "role": "orchestrator",
                "provider_model_keys": ["local_qwythos", "local_wrb"],
            },
            {
                "alias": "wrb_critic",
                "role": "exploit",
                "provider_model_keys": ["local_wrb", "local_qwythos"],
            },
            {
                "alias": "fast_triage",
                "role": "triage",
                "provider_model_keys": [
                    "local_gemma_fast",
                    "local_qwen_fast",
                    "local_qwythos",
                ],
            },
            {
                "alias": "code_utility",
                "role": "code",
                "provider_model_keys": ["local_qwen_fast", "local_qwythos"],
            },
            {
                "alias": "report_writer",
                "role": "report",
                "provider_model_keys": [
                    "local_qwythos",
                    "cloud_deepseek",
                    "cloud_openai",
                ],
            },
            {
                "alias": "quick_reporter",
                "role": "report",
                "provider_model_keys": ["local_qwythos"],
            },
            {
                "alias": "quick_planner",
                "role": "planner",
                "provider_model_keys": ["local_qwythos"],
            },
            {
                "alias": "quick_critic",
                "role": "security",
                "provider_model_keys": ["local_wrb", "local_qwythos"],
            },
            {
                "alias": "quick_triage",
                "role": "triage",
                "provider_model_keys": [
                    "local_gemma_fast",
                    "local_qwen_fast",
                ],
            },
        ]
        for item in defaults:
            self._aliases[item["alias"]] = AliasEntry(
                alias=item["alias"],
                provider_model_keys=item["provider_model_keys"],
                role=item.get("role", ""),
            )

    def resolve(self, alias: str) -> AliasEntry | None:
        return self._aliases.get(alias)

    def resolve_models(self, alias: str) -> list[ModelRecord]:
        entry = self._aliases.get(alias)
        if not entry:
            return []
        models: list[ModelRecord] = []
        for key in entry.provider_model_keys:
            record = self._provider_registry.get(key)
            if record is not None:
                models.append(record)
        return models

    def list_aliases(self) -> list[str]:
        return list(self._aliases.keys())

    def register(self, entry: AliasEntry) -> None:
        self._aliases[entry.alias] = entry


class ProviderHealthRegistry:
    def __init__(self) -> None:
        self._health: dict[str, ProviderHealth] = {}

    def get(self, provider_id: str) -> ProviderHealth:
        if provider_id not in self._health:
            self._health[provider_id] = ProviderHealth()
        return self._health[provider_id]

    def record_success(self, provider_id: str, latency_ms: int) -> None:
        self.get(provider_id).record_success(latency_ms)

    def record_failure(self, provider_id: str, error_code: str) -> None:
        self.get(provider_id).record_failure(error_code)

    def reset(self) -> None:
        self._health.clear()


class UnifiedRegistry:
    """Facade aggregating all registry components."""

    def __init__(self) -> None:
        self.providers = ProviderRegistry()
        self.models = ModelRegistry(self.providers)
        self.aliases = AliasRegistry(self.providers)
        self.health = ProviderHealthRegistry()

    def reset(self) -> None:
        self.providers = ProviderRegistry()
        self.models = ModelRegistry(self.providers)
        self.aliases = AliasRegistry(self.providers)
        self.health.reset()


_unified_registry: UnifiedRegistry | None = None


def get_unified_registry() -> UnifiedRegistry:
    global _unified_registry
    if _unified_registry is None:
        _unified_registry = UnifiedRegistry()
    return _unified_registry


def reset_unified_registry() -> None:
    global _unified_registry
    _unified_registry = None
