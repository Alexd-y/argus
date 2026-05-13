"""Integration tests for LLM Gateway routing — alias resolution, WRB-first
policy, cloud fallback chains, and error propagation.

All outbound HTTP calls are mocked. Tests needing a live LLM backend are
marked with ``@pytest.mark.skip``.
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from src.llm import (
    LLMAllProvidersFailedError,
    LLMProviderUnavailableError,
    call_llm,
    is_llm_available,
)
from src.llm.gateway_client import GatewayClient, GatewayClientError, GatewayResponse
from src.llm.model_aliases import (
    AliasRegistry,
    ModelAlias,
    ProviderConfig,
    get_alias_registry,
    reset_alias_registry,
)
from src.llm.policy import (
    Compliance,
    LLMPolicy,
    Profile,
    Routing,
    RouteConfig,
    build_effective_policy,
)
from src.llm.task_router import (
    LLMTask,
    LLMTaskResponse,
    ROUTING_TABLE,
    call_llm_for_task,
)


# ---------------------------------------------------------------------------
# Alias Registry
# ---------------------------------------------------------------------------


class TestAliasRegistry:
    """Model alias resolution — WRB-first + cloud fallback."""

    def test_default_aliases_loaded(self) -> None:
        registry = AliasRegistry()
        aliases = registry.list_all()
        assert len(aliases) >= 6

    def test_resolve_wrb_pentest_primary(self) -> None:
        registry = AliasRegistry()
        entry = registry.resolve("argus-pentest-primary")
        assert entry is not None
        assert entry.role == "pentest"
        assert len(entry.providers) >= 1
        assert entry.providers[0].key == "whiterabbitneo-7b"

    def test_resolve_planner_fast(self) -> None:
        registry = AliasRegistry()
        entry = registry.resolve("argus-planner-fast")
        assert entry is not None
        assert entry.role == "planner"
        assert entry.providers[0].key == "deepseek-v4-flash"

    def test_wrb_is_not_cloud(self) -> None:
        registry = AliasRegistry()
        assert registry.is_cloud("argus-pentest-primary") is False

    def test_planner_is_cloud(self) -> None:
        registry = AliasRegistry()
        assert registry.is_cloud("argus-planner-fast") is True

    def test_resolve_unknown_returns_none(self) -> None:
        registry = AliasRegistry()
        assert registry.resolve("nonexistent-alias") is None

    def test_get_aliases_for_role(self) -> None:
        registry = AliasRegistry()
        code_aliases = registry.get_aliases_for_role("code")
        assert len(code_aliases) >= 2
        assert "argus-code-cloud" in code_aliases
        assert "argus-code-local" in code_aliases

    def test_is_configured_checks_base_url(self) -> None:
        registry = AliasRegistry()
        assert registry.is_configured("argus-planner-fast") is True

    def test_load_from_config_merges(self) -> None:
        registry = AliasRegistry()
        registry.load_from_config(
            {
                "argus-custom": {
                    "role": "code",
                    "providers": [
                        {
                            "key": "custom-llm",
                            "base_url": "http://localhost:9999",
                            "model": "custom-model",
                        }
                    ],
                }
            }
        )
        entry = registry.resolve("argus-custom")
        assert entry is not None
        assert entry.providers[0].model == "custom-model"

    def test_singleton_reset(self) -> None:
        reset_alias_registry()
        reg1 = get_alias_registry()
        reset_alias_registry()
        reg2 = get_alias_registry()
        assert reg1 is not reg2


# ---------------------------------------------------------------------------
# Policy Builder
# ---------------------------------------------------------------------------


class TestPolicyBuilder:
    """Effective LLM policy construction from profiles and overrides."""

    def test_standard_profile_defaults(self) -> None:
        policy = build_effective_policy(tenant_id="t1", scan_id="s1")
        assert policy.profile == Profile.STANDARD
        assert policy.budget.max_cost_usd == 0.50
        assert policy.routing.planner.max_calls > 0

    def test_quick_profile_has_lower_limits(self) -> None:
        policy = build_effective_policy(profile=Profile.QUICK)
        assert policy.budget.max_cost_usd < 0.30

    def test_airgapped_compliance_flag(self) -> None:
        policy = build_effective_policy(
            compliance_overrides={"airgapped_only": True}
        )
        assert policy.compliance.airgapped_only is True

    def test_budget_overrides_merge(self) -> None:
        policy = build_effective_policy(
            budget_overrides={"max_cost_usd": 2.50, "soft_limit_usd": 2.00}
        )
        assert policy.budget.max_cost_usd == 2.50
        assert policy.budget.soft_limit_usd == 2.00

    def test_soft_limit_must_be_less_than_max(self) -> None:
        with pytest.raises(ValueError, match="soft_limit_usd"):
            build_effective_policy(
                budget_overrides={"max_cost_usd": 0.50, "soft_limit_usd": 0.90}
            )

    def test_local_only_route_rejects_cloud_alias(self) -> None:
        with pytest.raises(ValueError, match="local_only"):
            LLMPolicy(
                budget={"max_cost_usd": 1.0},
                routing={
                    "devsecops": {
                        "preferred_aliases": ["argus-planner-fast"],
                        "local_only": True,
                    }
                },
            )


# ---------------------------------------------------------------------------
# Task Router — routing table integrity
# ---------------------------------------------------------------------------


class TestTaskRouterTable:
    """Task routing table must be complete and consistent."""

    def test_every_llm_task_has_route(self) -> None:
        for task in LLMTask:
            assert task in ROUTING_TABLE, f"Missing route for {task.value}"

    def test_osint_task_maps_to_osint_role(self) -> None:
        from src.llm.task_router import _TASK_TO_ROLE

        assert _TASK_TO_ROLE[LLMTask.PERPLEXITY_OSINT] == "osint"

    def test_report_section_maps_to_report_role(self) -> None:
        from src.llm.task_router import _TASK_TO_ROLE

        assert _TASK_TO_ROLE[LLMTask.REPORT_SECTION] == "report"

    def test_perplexity_route_has_fallback_to_self(self) -> None:
        route = ROUTING_TABLE[LLMTask.PERPLEXITY_OSINT]
        assert route.fallback_env_key == "PERPLEXITY_API_KEY"

    @pytest.mark.asyncio
    async def test_task_router_returns_text_with_dedup(self) -> None:
        """DEDUP_ANALYSIS route mocked — verifies response shape."""
        mock_resp = type("Resp", (), {})()
        mock_resp.raise_for_status = lambda: None
        mock_resp.json = lambda: {
            "choices": [{"message": {"content": "dedup_result"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
        }

        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "sk-test"}):
            with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
                mock_post.return_value = mock_resp
                result = await call_llm_for_task(
                    LLMTask.DEDUP_ANALYSIS, "find duplicates"
                )
                assert isinstance(result, LLMTaskResponse)
                assert result.text == "dedup_result"
                assert result.provider == "DEEPSEEK_API_KEY"


# ---------------------------------------------------------------------------
# Gateway Client — error paths
# ---------------------------------------------------------------------------


class TestGatewayClientErrors:
    """LLM Gateway client maps HTTP errors to typed client errors."""

    @pytest.mark.asyncio
    async def test_403_policy_denied(self) -> None:
        err_resp = httpx.Response(403, json={"detail": {"code": "llm_policy_denied", "message": "Blocked by policy"}})
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = err_resp
            client = GatewayClient("http://localhost:8080")
            with pytest.raises(GatewayClientError, match="Blocked"):
                await client.chat_completion("gpt-4", [{"role": "user", "content": "hi"}])

    @pytest.mark.asyncio
    async def test_502_all_providers_failed(self) -> None:
        err_resp = httpx.Response(502)
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.return_value = err_resp
            client = GatewayClient("http://localhost:8080")
            with pytest.raises(GatewayClientError, match="All LLM providers failed"):
                await client.chat_completion("gpt-4", [{"role": "user", "content": "hi"}])

    @pytest.mark.asyncio
    async def test_timeout_raises(self) -> None:
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.TimeoutException("timed out")
            client = GatewayClient("http://localhost:8080")
            with pytest.raises(GatewayClientError, match="timed out"):
                await client.chat_completion("gpt-4", [{"role": "user", "content": "hi"}])

    @pytest.mark.asyncio
    async def test_connect_error_raises(self) -> None:
        with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
            mock_post.side_effect = httpx.ConnectError("refused")
            client = GatewayClient("http://localhost:8080")
            with pytest.raises(GatewayClientError, match="unreachable"):
                await client.chat_completion("gpt-4", [{"role": "user", "content": "hi"}])


# ---------------------------------------------------------------------------
# WRB-First Routing — facade integration (mocked)
# ---------------------------------------------------------------------------


class TestWRBFirstRouting:
    """WhiteRabbitNeo-first routing via the facade layer."""

    @pytest.mark.asyncio
    async def test_wrb_called_for_pentest_task(self) -> None:
        """THREAT_MODELING task routes through WRB first, no cloud fallback."""
        with patch(
            "src.llm.facade._get_wrb_adapter",
            return_value=MagicMock(
                is_configured=True,
            ),
        ):
            with patch(
                "src.llm.facade._call_via_whiterabbitneo",
                new_callable=AsyncMock,
                return_value="wrb-result",
            ) as mock_wrb:
                from src.llm.facade import call_llm_unified

                result = await call_llm_unified(
                    "system",
                    "user",
                    task=LLMTask.THREAT_MODELING,
                    phase="test",
                )
                assert result == "wrb-result"
                mock_wrb.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_osint_goes_directly_to_perplexity(self) -> None:
        """PERPLEXITY_OSINT bypasses WRB entirely."""
        with patch(
            "src.llm.facade._call_via_task_router",
            new_callable=AsyncMock,
            return_value="osint-result",
        ) as mock_task:
            from src.llm.facade import call_llm_unified

            result = await call_llm_unified(
                "sys",
                "user",
                task=LLMTask.PERPLEXITY_OSINT,
                phase="osint",
            )
            assert result == "osint-result"
            mock_task.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_wrb_unconfigured_falls_back_to_cloud(self) -> None:
        """When WRB has no base_url, cloud task_router is used."""
        with patch(
            "src.llm.facade._get_wrb_adapter",
            return_value=MagicMock(is_configured=False),
        ):
            with patch(
                "src.llm.facade._call_via_task_router",
                new_callable=AsyncMock,
                return_value="cloud-result",
            ) as mock_task:
                from src.llm.facade import call_llm_unified

                result = await call_llm_unified(
                    "sys",
                    "user",
                    task=LLMTask.REPORT_SECTION,
                    phase="reporting",
                )
                assert result == "cloud-result"
                mock_task.assert_awaited_once()


# ---------------------------------------------------------------------------
# Live backend — skipped in CI
# ---------------------------------------------------------------------------


@pytest.mark.skip(reason="requires live LLM backend")
class TestLiveLLMBackend:
    """Smoke tests requiring real LLM infrastructure (Docker stack)."""

    @pytest.mark.asyncio
    async def test_gateway_health(self) -> None:
        pass

    @pytest.mark.asyncio
    async def test_wrb_generates_content(self) -> None:
        pass
