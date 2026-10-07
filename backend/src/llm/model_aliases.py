"""Model Alias Registry — maps logical alias names to concrete providers/models.

Aliases are configurable, not hardcoded. The operator maps `argus-planner-fast`
to any provider/model. Loaded from env/config/DB at startup.

No vendor model names as product invariants.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from dataclasses import fields as _dc_fields
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ProviderConfig:
    key: str = ""  # whiterabbitneo-7b, deepseek-v4-flash, …
    base_url: str = ""
    model: str = ""
    cloud_allowed: bool = True
    price_input_per_million_usd: float = 0.0
    price_output_per_million_usd: float = 0.0


@dataclass
class ModelAlias:
    alias: str = ""
    role: str = ""  # pentest | planner | reasoning | code | devsecops | report | osint
    providers: list[ProviderConfig] = field(default_factory=list)


class AliasRegistry:
    def __init__(self) -> None:
        self._aliases: dict[str, ModelAlias] = {}
        self._load_defaults()

    def _load_defaults(self) -> None:
        defaults: list[dict[str, Any]] = [
            {
                "alias": "argus-pentest-primary",
                "role": "pentest",
                "providers": [
                    {
                        "key": "whiterabbitneo-7b",
                        "base_url": os.environ.get("WHITERABBITNEO_URL", ""),
                        "model": "taico-ai/WhiteRabbitNeo-v3-7B",
                        "cloud_allowed": False,
                        "price_input_per_million_usd": 0.0,
                        "price_output_per_million_usd": 0.0,
                    },
                ],
            },
            {
                "alias": "argus-planner-qwythos",
                "role": "planner",
                "providers": [
                    {
                        "key": "qwythos-9b",
                        "base_url": os.environ.get("QWYTHOS_URL", ""),
                        "model": "qwythos-9b-claude-mythos-5-1m",
                        "cloud_allowed": False,
                        "price_input_per_million_usd": 0.0,
                        "price_output_per_million_usd": 0.0,
                    },
                ],
            },
            {
                "alias": "argus-triage-fast",
                "role": "triage",
                "providers": [
                    {
                        "key": "gemma-2-2b",
                        "base_url": os.environ.get("GEMMA_LOCAL_URL", ""),
                        "model": "gemma-2-2b-it",
                        "cloud_allowed": False,
                        "price_input_per_million_usd": 0.0,
                        "price_output_per_million_usd": 0.0,
                    },
                ],
            },
            {
                "alias": "argus-planner-fast",
                "role": "planner",
                "providers": [
                    {
                        "key": "deepseek-v4-flash",
                        "base_url": "https://api.deepseek.com/v1",
                        "model": "deepseek-chat",
                        "cloud_allowed": True,
                        "price_input_per_million_usd": 0.14,
                        "price_output_per_million_usd": 0.28,
                    },
                ],
            },
            {
                "alias": "argus-planner-deep",
                "role": "reasoning",
                "providers": [
                    {
                        "key": "deepseek-v4-pro",
                        "base_url": "https://api.deepseek.com/v1",
                        "model": "deepseek-v4-pro",
                        "cloud_allowed": True,
                        "price_input_per_million_usd": 0.28,
                        "price_output_per_million_usd": 0.56,
                    },
                ],
            },
            {
                "alias": "argus-code-cloud",
                "role": "code",
                "providers": [
                    {
                        "key": "qwen3-coder-480b",
                        "base_url": "https://openrouter.ai/api/v1",
                        "model": "qwen/qwen3-coder:free",
                        "cloud_allowed": True,
                        "price_input_per_million_usd": 0.15,
                        "price_output_per_million_usd": 0.15,
                    },
                ],
            },
            {
                "alias": "argus-code-local",
                "role": "code",
                "providers": [
                    {
                        "key": "qwen3-32b-local",
                        "base_url": os.environ.get("QWEN_LOCAL_URL", ""),
                        "model": "qwen3-32b",
                        "cloud_allowed": False,
                        "price_input_per_million_usd": 0.0,
                        "price_output_per_million_usd": 0.0,
                    },
                ],
            },
            {
                "alias": "argus-devsecops-local",
                "role": "devsecops",
                "providers": [
                    {
                        "key": "whiterabbitneo-7b",
                        "base_url": os.environ.get("WHITERABBITNEO_URL", ""),
                        "model": "taico-ai/WhiteRabbitNeo-v3-7B",
                        "cloud_allowed": False,
                        "price_input_per_million_usd": 0.0,
                        "price_output_per_million_usd": 0.0,
                    },
                ],
            },
            {
                "alias": "argus-report",
                "role": "report",
                "providers": [
                    {
                        "key": "deepseek-v4-pro",
                        "base_url": "https://api.deepseek.com/v1",
                        "model": "deepseek-v4-pro",
                        "cloud_allowed": True,
                        "price_input_per_million_usd": 0.28,
                        "price_output_per_million_usd": 0.56,
                    },
                ],
            },
            {
                "alias": "argus-quick-report",
                "role": "report",
                "providers": [
                    {
                        "key": "qwythos-9b",
                        "base_url": os.environ.get("QWYTHOS_URL", ""),
                        "model": "qwythos-9b-claude-mythos-5-1m",
                        "cloud_allowed": False,
                        "price_input_per_million_usd": 0.0,
                        "price_output_per_million_usd": 0.0,
                    },
                ],
            },
            {
                "alias": "argus-osint",
                "role": "osint",
                "providers": [
                    {
                        "key": "perplexity",
                        "base_url": "https://api.perplexity.ai",
                        "model": "sonar",
                        "cloud_allowed": True,
                        "price_input_per_million_usd": 1.00,
                        "price_output_per_million_usd": 1.00,
                    },
                ],
            },
        ]

        for entry in defaults:
            providers = [ProviderConfig(**p) for p in entry["providers"]]
            self._aliases[entry["alias"]] = ModelAlias(
                alias=entry["alias"],
                role=entry["role"],
                providers=providers,
            )

    def load_from_config(self, config: dict[str, Any]) -> None:
        """Merge additional aliases from config dict (env YAML / JSON)."""
        for alias_name, alias_data in config.items():
            providers = []
            for p in alias_data.get("providers", []):
                providers.append(ProviderConfig(**p))
            self._aliases[alias_name] = ModelAlias(
                alias=alias_name,
                role=alias_data.get("role", "planner"),
                providers=providers,
            )

    async def load_from_db(self, session) -> None:
        """Merge per-tenant alias overrides from the ``llm_model_aliases`` table.

        DB rows take precedence over the env/config defaults (same semantics as
        :meth:`load_from_config`); tenant scoping is enforced by row-level security
        on the session. Best-effort: a missing table or query error leaves the
        env/config defaults intact (logged) rather than failing startup.
        """
        try:
            from sqlalchemy import select

            from src.db.models import LlmModelAlias

            result = await session.execute(select(LlmModelAlias))
            rows = list(result.scalars().all())
        except Exception:
            logger.debug(
                "load_from_db: alias table unavailable; keeping env/config defaults",
                exc_info=True,
            )
            return

        valid = {f.name for f in _dc_fields(ProviderConfig)}
        for row in rows:
            providers = [
                ProviderConfig(**{k: v for k, v in p.items() if k in valid})
                for p in (row.providers or [])
                if isinstance(p, dict)
            ]
            self._aliases[str(row.alias)] = ModelAlias(
                alias=str(row.alias),
                role=str(row.role or "planner"),
                providers=providers,
            )

    def resolve(self, alias: str) -> ModelAlias | None:
        return self._aliases.get(alias)

    def get_aliases_for_role(self, role: str) -> list[str]:
        return [a.alias for a in self._aliases.values() if a.role == role]

    def list_all(self) -> list[ModelAlias]:
        return list(self._aliases.values())

    def is_cloud(self, alias: str) -> bool:
        entry = self._aliases.get(alias)
        if not entry or not entry.providers:
            return False
        return entry.providers[0].cloud_allowed

    def is_configured(self, alias: str) -> bool:
        entry = self._aliases.get(alias)
        if not entry or not entry.providers:
            return False
        return bool(entry.providers[0].base_url)


# Singleton
_registry: AliasRegistry | None = None


def get_alias_registry() -> AliasRegistry:
    global _registry
    if _registry is None:
        _registry = AliasRegistry()
    return _registry


def reset_alias_registry() -> None:
    global _registry
    _registry = None
