"""Tests for LLM Gateway routing and policy enforcement."""

import pytest
from unittest.mock import AsyncMock, patch

from src.llm_gateway.router import (
    GatewayRequest, GatewayResponse, PolicyDeniedError, AllProvidersFailedError,
)
from src.llm_gateway.policy_enforcer import PolicyEnforcer
from src.llm_gateway.provider_clients import ProviderRouter, ALIAS_REGISTRY
from src.llm_gateway.cost_router import CostRouter


class TestPolicyEnforcer:
    def setup_method(self):
        self.enforcer = PolicyEnforcer()

    def test_empty_policy_passes(self):
        # Should not raise
        self.enforcer.evaluate({}, None)

    def test_airgapped_blocks_cloud_alias(self):
        policy = {"compliance": {"airgapped_only": True}}
        request = type("req", (), {"model": "argus-planner-fast", "metadata": {}})()

        with pytest.raises(PolicyDeniedError, match="(?i)airgapped.*cloud"):
            self.enforcer.evaluate(policy, request)

    def test_airgapped_allows_local_alias(self):
        policy = {"compliance": {"airgapped_only": True}}
        request = type("req", (), {"model": "argus-pentest-primary", "metadata": {}})()

        # Should not raise
        self.enforcer.evaluate(policy, request)

    def test_no_cloud_for_source_code_blocks_cloud(self):
        policy = {"compliance": {"no_cloud_llm_for_source_code": True}}
        request = type("req", (), {"model": "argus-planner-fast", "metadata": {"content_class": "source_code"}})()

        with pytest.raises(PolicyDeniedError, match="(?i)source.code.*cloud"):
            self.enforcer.evaluate(policy, request)

    def test_no_cloud_for_source_code_allows_wrb(self):
        policy = {"compliance": {"no_cloud_llm_for_source_code": True}}
        request = type("req", (), {"model": "argus-pentest-primary", "metadata": {"content_class": "source_code"}})()

        self.enforcer.evaluate(policy, request)  # Should not raise

    def test_budget_exceeded_denies(self):
        policy = {"budget": {"max_cost_usd": 0.0}}
        request = type("req", (), {"model": "argus-pentest-primary", "metadata": {}})()

        with pytest.raises(PolicyDeniedError, match="budget"):
            self.enforcer.evaluate(policy, request)


class TestAliasRegistry:
    def test_has_all_aliases(self):
        expected = [
            "argus-pentest-primary", "argus-planner-fast", "argus-planner-deep",
            "argus-code-cloud", "argus-code-local", "argus-devsecops-local",
            "argus-report", "argus-osint",
        ]
        for alias in expected:
            assert alias in ALIAS_REGISTRY, f"Missing alias: {alias}"

    def test_wrb_is_local(self):
        p = ALIAS_REGISTRY["argus-pentest-primary"]["providers"][0]
        assert p["cloud_allowed"] is False

    def test_deepseek_is_cloud(self):
        p = ALIAS_REGISTRY["argus-planner-fast"]["providers"][0]
        assert p["cloud_allowed"] is True


class TestCostRouter:
    def test_can_afford_within_budget(self):
        r = CostRouter(max_cost_usd=1.0)
        assert r.can_afford(0.5) is True

    def test_cannot_afford_over_budget(self):
        r = CostRouter(max_cost_usd=1.0)
        r.record_spend(0.9)
        assert r.can_afford(0.2) is False

    def test_no_budget_always_affords(self):
        r = CostRouter(max_cost_usd=0.0)
        assert r.can_afford(100.0) is True

    def test_soft_limit_detected(self):
        r = CostRouter(max_cost_usd=1.0)
        r.record_spend(0.85)
        assert r.over_soft_limit is True

    def test_remaining_tracks(self):
        r = CostRouter(max_cost_usd=1.0)
        r.record_spend(0.3)
        assert r.remaining == 0.7


class TestProviderRouter:
    def setup_method(self):
        self.router = ProviderRouter()

    @pytest.mark.asyncio
    async def test_select_known_alias(self):
        provider = await self.router.select_provider("argus-pentest-primary")
        assert provider["key"] == "whiterabbitneo-7b"

    @pytest.mark.asyncio
    async def test_select_unknown_alias_raises(self):
        with pytest.raises(AllProvidersFailedError, match="Unknown"):
            await self.router.select_provider("nonexistent")

    @pytest.mark.asyncio
    async def test_airgapped_filters_cloud_providers(self):
        policy = {"compliance": {"airgapped_only": True}}
        with pytest.raises(AllProvidersFailedError):
            await self.router.select_provider("argus-planner-fast", policy)
