"""Integration tests for LLM Gateway end-to-end flows.

Tests: gateway request → policy enforcement → routing → cloud fallback.
All external HTTP calls are mocked.
"""

import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.llm_gateway.router import (
    GatewayRequest, ChatMessage, GatewayResponse,
    PolicyDeniedError, AllProvidersFailedError,
)
from src.llm_gateway.policy_enforcer import PolicyEnforcer
from src.llm_gateway.provider_clients import ProviderRouter, ALIAS_REGISTRY


class TestGatewayStandardPolicy:
    def setup_method(self):
        self.enforcer = PolicyEnforcer()

    def test_standard_policy_passes(self):
        policy = {
            "budget": {"max_cost_usd": 1.0},
            "compliance": {"airgapped_only": False},
            "osint": {"enabled": True},
        }
        req = type("req", (), {"model": "argus-pentest-primary", "metadata": {}})()
        self.enforcer.evaluate(policy, req)  # should not raise

    def test_airgapped_blocks_deepseek(self):
        policy = {"compliance": {"airgapped_only": True}}
        req = type("req", (), {"model": "argus-planner-fast", "metadata": {}})()

        with pytest.raises(PolicyDeniedError, match="[Aa]irgapped"):
            self.enforcer.evaluate(policy, req)

    def test_airgapped_allows_wrb(self):
        policy = {"compliance": {"airgapped_only": True}}
        req = type("req", (), {"model": "argus-pentest-primary", "metadata": {}})()

        self.enforcer.evaluate(policy, req)  # should not raise

    def test_source_code_blocks_cloud(self):
        policy = {"compliance": {"no_cloud_llm_for_source_code": True}}
        req = type("req", (), {"model": "argus-planner-fast", "metadata": {"content_class": "source_code"}})()

        with pytest.raises(PolicyDeniedError, match="source.code.*cloud"):
            self.enforcer.evaluate(policy, req)

    def test_source_code_allows_wrb(self):
        policy = {"compliance": {"no_cloud_llm_for_source_code": True}}
        req = type("req", (), {"model": "argus-pentest-primary", "metadata": {"content_class": "source_code"}})()

        self.enforcer.evaluate(policy, req)  # should not raise

    def test_osint_disabled_blocks(self):
        policy = {"osint": {"enabled": False}}
        req = type("req", (), {"model": "argus-osint", "metadata": {}})()

        with pytest.raises(PolicyDeniedError, match="OSINT.*disabled"):
            self.enforcer.evaluate(policy, req)

    def test_budget_exceeded_blocks(self):
        policy = {"budget": {"max_cost_usd": 0.0}}
        req = type("req", (), {"model": "argus-pentest-primary", "metadata": {}})()

        with pytest.raises(PolicyDeniedError, match="budget"):
            self.enforcer.evaluate(policy, req)


class TestProviderRouting:
    def setup_method(self):
        self.router = ProviderRouter()

    @pytest.mark.asyncio
    async def test_wrb_primary_selected(self):
        provider = await self.router.select_provider("argus-pentest-primary")
        assert provider["key"] == "whiterabbitneo-7b"
        assert provider["cloud_allowed"] is False
        assert provider["model"] == "taico-ai/WhiteRabbitNeo-v3-7B"

    @pytest.mark.asyncio
    async def test_deepseek_cloud_selected(self):
        provider = await self.router.select_provider("argus-planner-fast")
        assert provider["key"] == "deepseek-v4-flash"
        assert provider["cloud_allowed"] is True

    @pytest.mark.asyncio
    async def test_perplexity_osint_selected(self):
        provider = await self.router.select_provider("argus-osint")
        assert provider["key"] == "perplexity"
        assert provider["model"] == "sonar"

    @pytest.mark.asyncio
    async def test_unknown_alias_raises(self):
        with pytest.raises(AllProvidersFailedError, match="Unknown"):
            await self.router.select_provider("nonexistent-alias")

    @pytest.mark.asyncio
    async def test_airgapped_filters_deepseek(self):
        policy = {"compliance": {"airgapped_only": True}}
        with pytest.raises(AllProvidersFailedError):
            await self.router.select_provider("argus-planner-fast", policy)


class TestMockedGatewayCall:
    @pytest.mark.asyncio
    async def test_call_returns_content(self):
        router = ProviderRouter()
        provider = await router.select_provider("argus-pentest-primary")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": '{"result": "ok"}'}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient.post", return_value=mock_resp):
            raw = await router.call_provider(
                provider,
                [{"role": "user", "content": "test"}],
                temperature=0.2,
                max_tokens=100,
            )

        assert raw["content"] == '{"result": "ok"}'
        assert raw["usage"]["prompt_tokens"] == 10
        assert raw["usage"]["completion_tokens"] == 5
        assert raw["provider"] == "whiterabbitneo-7b"


class TestUsageLedger:
    def test_records_and_summarizes(self):
        from src.llm_gateway.usage_ledger import record_usage, get_usage_summary, _ledger

        # Clear ledger
        _ledger.clear()

        record_usage(
            tenant_id="t1", scan_id="s1", phase="recon", task="orchestration",
            alias="argus-pentest-primary", provider="whiterabbitneo-7b",
            model="WRB-7B", prompt_tokens=100, completion_tokens=50,
            estimated_cost=0.0,
        )
        record_usage(
            tenant_id="t1", scan_id="s1", phase="reporting", task="report_section",
            alias="argus-report", provider="deepseek-v4-pro",
            model="deepseek-v4-pro", prompt_tokens=80, completion_tokens=60,
            estimated_cost=0.02,
        )

        summary = get_usage_summary(tenant_id="t1", scan_id="s1")
        assert summary["total_calls"] == 2
        assert summary["total_tokens"] == 290
        assert "whiterabbitneo-7b" in summary["by_provider"]
        assert "deepseek-v4-pro" in summary["by_provider"]


class TestRedactionIntegration:
    def test_end_to_end_redaction(self):
        from src.llm_gateway.redaction import (
            hash_prompt, log_prompt, log_response, redact_api_keys,
        )

        prompt = "API key: sk-proj-abc123 and bearer eyJhbGciOiJIUzI1NiJ9.token"
        cleaned = redact_api_keys(prompt)
        assert "sk-proj-" not in cleaned
        assert "eyJ" not in cleaned
        assert "REDACTED" in cleaned

        hashed = log_prompt(prompt, mode="hashed")
        assert len(hashed) == 32
        assert "sk-" not in hashed

        summary = log_response(prompt, mode="summary_only")
        assert len(summary) <= 503  # 500 + "..."

        off = log_prompt(prompt, mode="off")
        assert off == "<prompt_logging_off>"
