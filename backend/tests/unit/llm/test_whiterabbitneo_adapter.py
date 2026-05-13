"""Unit tests for WhiteRabbitNeo adapter."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.llm.whiterabbitneo_adapter import (
    WhiteRabbitNeoAdapter,
    get_whiterabbitneo_adapter,
    reset_whiterabbitneo_adapter,
    WRB_DEFAULT_MODEL,
)


class TestWhiteRabbitNeoAdapter:
    def test_not_configured_when_empty_url(self):
        adapter = WhiteRabbitNeoAdapter(base_url="")
        assert not adapter.is_configured
        assert not adapter.is_available()

    def test_configured_when_url_set(self):
        adapter = WhiteRabbitNeoAdapter(base_url="http://localhost:8000/v1")
        assert adapter.is_configured
        assert adapter.is_available()

    def test_base_url_strips_trailing_slash(self):
        adapter = WhiteRabbitNeoAdapter(base_url="http://localhost:8000/v1/")
        assert adapter.base_url == "http://localhost:8000/v1"

    @pytest.mark.asyncio
    async def test_call_raises_when_not_configured(self):
        adapter = WhiteRabbitNeoAdapter(base_url="")
        with pytest.raises(RuntimeError, match="not configured"):
            await adapter.call("test prompt")

    @pytest.mark.asyncio
    async def test_call_sends_correct_payload(self):
        adapter = WhiteRabbitNeoAdapter(base_url="http://wr:8000/v1", api_key="key123")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "test response"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }

        with patch(
            "httpx.AsyncClient.post",
            new=AsyncMock(return_value=mock_response),
        ) as mock_post:
            text = await adapter.call("user prompt", system_prompt="system prompt")

        assert text == "test response"
        mock_post.assert_called_once()
        call_args = mock_post.call_args
        payload = call_args[1]["json"]
        assert payload["model"] == WRB_DEFAULT_MODEL
        assert len(payload["messages"]) == 2
        assert payload["messages"][0]["role"] == "system"
        assert payload["messages"][1]["role"] == "user"

    @pytest.mark.asyncio
    async def test_call_sends_api_key_header(self):
        adapter = WhiteRabbitNeoAdapter(base_url="http://wr:8000/v1", api_key="secret")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "ok"}}],
        }

        with patch(
            "httpx.AsyncClient.post",
            new=AsyncMock(return_value=mock_response),
        ) as mock_post:
            await adapter.call("test")

        headers = mock_post.call_args[1]["headers"]
        assert headers["Authorization"] == "Bearer secret"

    @pytest.mark.asyncio
    async def test_call_no_api_key_header_when_empty(self):
        adapter = WhiteRabbitNeoAdapter(base_url="http://wr:8000/v1", api_key="")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "ok"}}],
        }

        with patch(
            "httpx.AsyncClient.post",
            new=AsyncMock(return_value=mock_response),
        ) as mock_post:
            await adapter.call("test")

        headers = mock_post.call_args[1]["headers"]
        assert "Authorization" not in headers

    @pytest.mark.asyncio
    async def test_call_with_usage_returns_tokens(self):
        adapter = WhiteRabbitNeoAdapter(base_url="http://wr:8000/v1")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "result"}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        }

        with patch(
            "httpx.AsyncClient.post",
            new=AsyncMock(return_value=mock_response),
        ):
            text, usage = await adapter.call_with_usage("test prompt")

        assert text == "result"
        assert usage["prompt_tokens"] == 100
        assert usage["completion_tokens"] == 50
        assert usage["total_tokens"] == 150

    @pytest.mark.asyncio
    async def test_health_check_available(self):
        adapter = WhiteRabbitNeoAdapter(base_url="http://wr:8000/v1")

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": [{"id": "model1"}, {"id": "model2"}]}

        with patch(
            "httpx.AsyncClient.get",
            new=AsyncMock(return_value=mock_response),
        ):
            result = await adapter.health_check()

        assert result["status"] == "available"
        assert result["models"] == 2

    def test_health_check_unconfigured(self):
        adapter = WhiteRabbitNeoAdapter(base_url="")
        # health_check is async, run synchronously
        import asyncio
        result = asyncio.run(adapter.health_check())
        assert result["status"] == "unconfigured"


class TestAdapterSingleton:
    def teardown_method(self):
        reset_whiterabbitneo_adapter()

    def test_get_returns_same_instance(self):
        a1 = get_whiterabbitneo_adapter()
        a2 = get_whiterabbitneo_adapter()
        assert a1 is a2

    def test_reset_creates_new_instance(self):
        a1 = get_whiterabbitneo_adapter()
        reset_whiterabbitneo_adapter()
        a2 = get_whiterabbitneo_adapter()
        assert a1 is not a2
