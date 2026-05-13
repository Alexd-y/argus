"""Unit tests for facade WRB-first routing logic."""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock

from src.llm.task_router import LLMTask
from src.llm.facade import _CLOUD_FALLBACK_TASKS


class TestCloudFallbackTasks:
    def test_report_section_is_cloud_fallback(self):
        assert LLMTask.REPORT_SECTION in _CLOUD_FALLBACK_TASKS

    def test_executive_summary_is_cloud_fallback(self):
        assert LLMTask.EXECUTIVE_SUMMARY in _CLOUD_FALLBACK_TASKS

    def test_cost_summary_is_cloud_fallback(self):
        assert LLMTask.COST_SUMMARY in _CLOUD_FALLBACK_TASKS

    def test_perplexity_osint_is_cloud_fallback(self):
        assert LLMTask.PERPLEXITY_OSINT in _CLOUD_FALLBACK_TASKS

    def test_pentest_tasks_are_not_cloud_fallback(self):
        """Pentest analysis tasks must NOT have cloud fallback."""
        pentest_tasks = [
            LLMTask.ORCHESTRATION,
            LLMTask.THREAT_MODELING,
            LLMTask.ZERO_DAY_ANALYSIS,
            LLMTask.EXPLOIT_GENERATION,
            LLMTask.REMEDIATION_PLAN,
            LLMTask.VALIDATION_ONESHOT,
            LLMTask.DEDUP_ANALYSIS,
            LLMTask.POC_GENERATION,
        ]
        for task in pentest_tasks:
            assert task not in _CLOUD_FALLBACK_TASKS, f"{task} should NOT have cloud fallback"


class TestCallLlmUnifiedWrbRouting:
    @pytest.mark.asyncio
    async def test_wrb_configured_routes_pentest_task(self):
        """When WRB is configured, pentest tasks go to WRB directly."""
        from src.llm.facade import call_llm_unified
        from src.llm.whiterabbitneo_adapter import get_whiterabbitneo_adapter

        wrb = get_whiterabbitneo_adapter()
        orig_url = wrb._base_url
        try:
            wrb._base_url = "http://wrb:8000/v1"

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.json.return_value = {
                "choices": [{"message": {"content": "{}"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 2, "total_tokens": 7},
            }

            with patch(
                "httpx.AsyncClient.post",
                new=AsyncMock(return_value=mock_response),
            ) as mock_post:
                result = await call_llm_unified(
                    "system", "user", task=LLMTask.ORCHESTRATION
                )

            assert result == "{}"
            call_url = mock_post.call_args[0][0] if mock_post.call_args[0] else mock_post.call_args[1].get("url", "")
            assert "wrb:8000" in str(call_url) or "wrb:8000" in str(mock_post.call_args)
        finally:
            wrb._base_url = orig_url

    @pytest.mark.asyncio
    async def test_perplexity_osint_bypasses_wrb(self):
        """OSINT tasks go directly to cloud — WRB has no internet access."""
        from src.llm.facade import call_llm_unified
        from src.llm.whiterabbitneo_adapter import get_whiterabbitneo_adapter

        wrb = get_whiterabbitneo_adapter()
        orig_url = wrb._base_url
        try:
            wrb._base_url = "http://wrb:8000/v1"

            with patch("src.llm.facade._call_via_task_router", new_callable=AsyncMock) as mock_task_router:
                mock_task_router.return_value = "osint result"
                result = await call_llm_unified(
                    "system", "user", task=LLMTask.PERPLEXITY_OSINT
                )

            assert result == "osint result"
            mock_task_router.assert_called_once()
        finally:
            wrb._base_url = orig_url

    @pytest.mark.asyncio
    async def test_report_task_falls_back_to_cloud_on_wrb_failure(self):
        """Report tasks get cloud fallback when WRB fails."""
        from src.llm.facade import call_llm_unified
        from src.llm.whiterabbitneo_adapter import get_whiterabbitneo_adapter

        wrb = get_whiterabbitneo_adapter()
        orig_url = wrb._base_url
        try:
            wrb._base_url = "http://wrb:8000/v1"

            # WRB fails
            mock_fail = MagicMock()
            mock_fail.status_code = 500
            mock_fail.raise_for_status.side_effect = Exception("WRB down")

            # Cloud succeeds
            with patch(
                "httpx.AsyncClient.post",
                new=AsyncMock(return_value=mock_fail),
            ), \
                 patch("src.llm.facade._call_via_task_router", new_callable=AsyncMock) as mock_cloud:
                mock_cloud.return_value = "cloud fallback result"

                result = await call_llm_unified(
                    "system", "user", task=LLMTask.REPORT_SECTION
                )

            assert result == "cloud fallback result"
            mock_cloud.assert_called_once()
        finally:
            wrb._base_url = orig_url

    @pytest.mark.asyncio
    async def test_pentest_task_raises_on_wrb_failure(self):
        """Pentest tasks MUST raise when WRB fails — no cloud fallback."""
        from src.llm.facade import call_llm_unified
        from src.llm.whiterabbitneo_adapter import get_whiterabbitneo_adapter

        wrb = get_whiterabbitneo_adapter()
        orig_url = wrb._base_url
        try:
            wrb._base_url = "http://wrb:8000/v1"

            mock_fail = MagicMock()
            mock_fail.status_code = 500
            mock_fail.raise_for_status.side_effect = Exception("WRB down")

            with patch(
                "httpx.AsyncClient.post",
                new=AsyncMock(return_value=mock_fail),
            ):
                with pytest.raises(RuntimeError, match="WhiteRabbitNeo unavailable"):
                    await call_llm_unified(
                        "system", "user", task=LLMTask.ORCHESTRATION
                    )
        finally:
            wrb._base_url = orig_url


class TestTokenCounting:
    def test_tiktoken_encoding(self):
        from src.llm.facade import _count_tokens_tiktoken
        count = _count_tokens_tiktoken("Hello, world!")
        assert count > 0
        assert isinstance(count, int)

    def test_tiktoken_encoding_cached(self):
        from src.llm.facade import _count_tokens_tiktoken, _tiktoken_enc
        _count_tokens_tiktoken("first call")
        enc1 = _tiktoken_enc
        _count_tokens_tiktoken("second call")
        assert _tiktoken_enc is enc1  # cached
