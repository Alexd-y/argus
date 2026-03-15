"""Tests for ARGUS-008 LLM adapters and router."""

import logging
import os
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from src.llm import (
    LLMAllProvidersFailedError,
    LLMProviderUnavailableError,
    call_llm,
    is_llm_available,
)
from src.llm.adapters import (
    GeminiAdapter,
    OpenAICompatibleAdapter,
)


class TestIsLLMAvailable:
    """is_llm_available()"""

    @pytest.mark.asyncio
    async def test_returns_false_when_no_keys(self) -> None:
        """Returns False when no LLM keys are set."""
        with patch.dict(os.environ, {}, clear=True):
            # Clear known keys
            for k in (
                "OPENAI_API_KEY",
                "DEEPSEEK_API_KEY",
                "OPENROUTER_API_KEY",
                "GOOGLE_API_KEY",
                "KIMI_API_KEY",
                "PERPLEXITY_API_KEY",
            ):
                os.environ.pop(k, None)
            assert is_llm_available() is False

    @pytest.mark.asyncio
    async def test_returns_true_when_key_present(self) -> None:
        """Returns True when at least one key is set."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            assert is_llm_available() is True


class TestCallLLM:
    """call_llm() with mocked HTTP."""

    @pytest.mark.asyncio
    async def test_raises_when_no_provider(self) -> None:
        """Raises RuntimeError when no provider configured."""
        with patch.dict(os.environ, {}, clear=True):
            for k in (
                "OPENAI_API_KEY",
                "DEEPSEEK_API_KEY",
                "OPENROUTER_API_KEY",
                "GOOGLE_API_KEY",
                "KIMI_API_KEY",
                "PERPLEXITY_API_KEY",
            ):
                os.environ.pop(k, None)
            with pytest.raises(LLMProviderUnavailableError, match="No LLM provider configured"):
                await call_llm("test prompt")

    @pytest.mark.asyncio
    async def test_returns_content_when_mock_succeeds(self) -> None:
        """Returns LLM response when mocked HTTP succeeds."""
        mock_response = {
            "choices": [{"message": {"content": "Hello from LLM"}}],
        }
        mock_resp = type("Resp", (), {})()
        mock_resp.json = lambda: mock_response
        mock_resp.raise_for_status = lambda: None

        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.llm.adapters.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_resp)
                mock_client_cls.return_value.__aenter__ = AsyncMock(
                    return_value=mock_client
                )
                mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=None)

                result = await call_llm("Hi", system_prompt="You are helpful")
                assert result == "Hello from LLM"

    @pytest.mark.asyncio
    async def test_timeout_raises_after_all_adapters_fail(self) -> None:
        """Raises RuntimeError when all adapters fail with timeout."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.llm.adapters.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(
                    side_effect=httpx.TimeoutException("Request timed out")
                )
                mock_client_cls.return_value.__aenter__ = AsyncMock(
                    return_value=mock_client
                )
                mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=None)

                with pytest.raises(LLMAllProvidersFailedError, match="All LLM providers failed"):
                    await call_llm("Hi")

    @pytest.mark.asyncio
    async def test_rate_limit_429_raises_after_all_adapters_fail(self) -> None:
        """Raises RuntimeError when all adapters fail with 429 rate limit."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.llm.adapters.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(
                    side_effect=httpx.HTTPStatusError(
                        "429 Too Many Requests",
                        request=httpx.Request("POST", "https://api.openai.com/v1/chat/completions"),
                        response=httpx.Response(429),
                    )
                )
                mock_client_cls.return_value.__aenter__ = AsyncMock(
                    return_value=mock_client
                )
                mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=None)

                with pytest.raises(LLMAllProvidersFailedError, match="All LLM providers failed"):
                    await call_llm("Hi")

    @pytest.mark.asyncio
    async def test_malformed_api_json_raises_after_all_adapters_fail(self) -> None:
        """Raises when API returns non-JSON body (e.g. HTML error page)."""
        def _raise_json_error() -> None:
            raise ValueError("Invalid JSON: <html>Server Error</html>")

        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.llm.adapters.httpx.AsyncClient") as mock_client_cls:
                mock_resp = type("Resp", (), {})()
                mock_resp.raise_for_status = lambda: None
                mock_resp.json = _raise_json_error
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(return_value=mock_resp)
                mock_client_cls.return_value.__aenter__ = AsyncMock(
                    return_value=mock_client
                )
                mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=None)

                with pytest.raises(LLMAllProvidersFailedError, match="All LLM providers failed"):
                    await call_llm("Hi")

    @pytest.mark.asyncio
    async def test_no_api_key_leak_in_error_message(self, caplog: pytest.LogCaptureFixture) -> None:
        """Error messages must not contain API keys."""
        secret_key = "sk-secret-key-never-leak-12345"
        with patch.dict(os.environ, {"OPENAI_API_KEY": secret_key}):
            with patch("src.llm.adapters.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(
                    side_effect=ValueError(
                        f"Connection failed for https://api.example.com?key={secret_key}"
                    )
                )
                mock_client_cls.return_value.__aenter__ = AsyncMock(
                    return_value=mock_client
                )
                mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=None)

                with caplog.at_level(logging.WARNING):
                    with pytest.raises(LLMAllProvidersFailedError) as exc_info:
                        await call_llm("Hi")

        err_msg = str(exc_info.value)
        assert secret_key not in err_msg, "API key must not appear in raised error message"
        for record in caplog.records:
            assert secret_key not in record.message, "API key must not appear in logs"

    @pytest.mark.asyncio
    async def test_no_api_key_leak_in_logs(self, caplog: pytest.LogCaptureFixture) -> None:
        """Logs must not contain API keys when adapter fails."""
        secret_key = "sk-log-leak-test-xyz"
        with patch.dict(os.environ, {"OPENAI_API_KEY": secret_key}):
            with patch("src.llm.adapters.httpx.AsyncClient") as mock_client_cls:
                mock_client = AsyncMock()
                mock_client.post = AsyncMock(
                    side_effect=httpx.ConnectError("Connection refused")
                )
                mock_client_cls.return_value.__aenter__ = AsyncMock(
                    return_value=mock_client
                )
                mock_client_cls.return_value.__aexit__ = AsyncMock(return_value=None)

                with caplog.at_level(logging.DEBUG), pytest.raises(LLMAllProvidersFailedError):
                    await call_llm("Hi")

        for record in caplog.records:
            assert secret_key not in record.message
            assert secret_key not in str(record.args)


class TestOpenAICompatibleAdapter:
    """OpenAICompatibleAdapter."""

    def test_is_available_false_when_no_key(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("OPENAI_API_KEY", None)
            adapter = OpenAICompatibleAdapter(
                "OPENAI_API_KEY", "https://api.openai.com", "gpt-4o-mini"
            )
            assert adapter.is_available() is False

    def test_is_available_true_when_key_set(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-x"}):
            adapter = OpenAICompatibleAdapter(
                "OPENAI_API_KEY", "https://api.openai.com", "gpt-4o-mini"
            )
            assert adapter.is_available() is True


class TestGeminiAdapter:
    """GeminiAdapter."""

    def test_is_available_false_when_no_key(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GOOGLE_API_KEY", None)
            adapter = GeminiAdapter()
            assert adapter.is_available() is False

    def test_is_available_true_when_key_set(self) -> None:
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test-key"}):
            adapter = GeminiAdapter()
            assert adapter.is_available() is True
