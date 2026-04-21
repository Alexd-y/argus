"""Unit tests for :mod:`src.orchestrator.llm_provider` (ARG-008)."""

from __future__ import annotations

from uuid import uuid4

import pytest

from src.orchestrator.llm_provider import (
    EchoLLMProvider,
    LLMProvider,
    LLMProviderUnavailableError,
    LLMRequest,
    LLMResponse,
    OpenAILLMProvider,
    ResponseFormat,
)


def _make_request(
    *,
    prompt_id: str = "demo_v1",
    response_format: ResponseFormat = ResponseFormat.JSON_OBJECT,
    expected_schema: dict[str, object] | None = None,
) -> LLMRequest:
    return LLMRequest(
        correlation_id=uuid4(),
        model_id="test-model-1",
        prompt_id=prompt_id,
        system_prompt="system",
        user_prompt="user",
        max_tokens=128,
        temperature=0.0,
        response_format=response_format,
        expected_schema=expected_schema,
    )


class TestLLMRequest:
    def test_json_schema_format_requires_schema(self) -> None:
        with pytest.raises(ValueError, match="expected_schema must be provided"):
            _make_request(
                response_format=ResponseFormat.JSON_SCHEMA,
                expected_schema=None,
            )

    def test_json_object_format_does_not_require_schema(self) -> None:
        req = _make_request(response_format=ResponseFormat.JSON_OBJECT)
        assert req.expected_schema is None
        assert req.response_format is ResponseFormat.JSON_OBJECT

    def test_max_tokens_upper_bound_enforced(self) -> None:
        with pytest.raises(ValueError):
            LLMRequest(
                correlation_id=uuid4(),
                model_id="m",
                prompt_id="p",
                system_prompt="s",
                user_prompt="u",
                max_tokens=99_999,
                temperature=0.0,
            )

    def test_temperature_upper_bound_enforced(self) -> None:
        with pytest.raises(ValueError):
            LLMRequest(
                correlation_id=uuid4(),
                model_id="m",
                prompt_id="p",
                system_prompt="s",
                user_prompt="u",
                max_tokens=128,
                temperature=2.0,
            )


class TestLLMResponseFinishReason:
    def test_unknown_finish_reason_rejected(self) -> None:
        with pytest.raises(ValueError, match="finish_reason"):
            LLMResponse(
                correlation_id=uuid4(),
                content="x",
                model_id="m",
                prompt_tokens=1,
                completion_tokens=1,
                usd_cost=0.0,
                latency_ms=0,
                finish_reason="bogus",
            )

    def test_known_finish_reasons_accepted(self) -> None:
        for reason in ("stop", "length", "tool_calls", "content_filter", "echo"):
            resp = LLMResponse(
                correlation_id=uuid4(),
                content="x",
                model_id="m",
                prompt_tokens=1,
                completion_tokens=1,
                usd_cost=0.0,
                latency_ms=0,
                finish_reason=reason,
            )
            assert resp.finish_reason == reason


class TestEchoLLMProvider:
    @pytest.mark.asyncio
    async def test_returns_canned_dict_response(self) -> None:
        provider = EchoLLMProvider()
        provider.register_canned("demo_v1", {"answer": 42})
        request = _make_request(prompt_id="demo_v1")
        response = await provider.call(request)
        assert response.parsed_json == {"answer": 42}
        assert response.finish_reason == "echo"
        assert response.model_id == "test-model-1"
        assert response.correlation_id == request.correlation_id

    @pytest.mark.asyncio
    async def test_returns_canned_string_response(self) -> None:
        provider = EchoLLMProvider()
        provider.register_canned("demo_v1", '{"answer": 42}')
        request = _make_request(prompt_id="demo_v1")
        response = await provider.call(request)
        assert response.content == '{"answer": 42}'
        assert response.parsed_json == {"answer": 42}

    @pytest.mark.asyncio
    async def test_text_format_does_not_parse_json(self) -> None:
        provider = EchoLLMProvider()
        provider.register_canned("demo_v1", "free text")
        request = _make_request(
            prompt_id="demo_v1", response_format=ResponseFormat.TEXT
        )
        response = await provider.call(request)
        assert response.parsed_json is None
        assert response.content == "free text"

    @pytest.mark.asyncio
    async def test_invalid_json_returns_parsed_none(self) -> None:
        provider = EchoLLMProvider()
        provider.register_canned("demo_v1", "not valid json")
        request = _make_request(prompt_id="demo_v1")
        response = await provider.call(request)
        assert response.parsed_json is None
        assert response.content == "not valid json"

    @pytest.mark.asyncio
    async def test_unregistered_prompt_id_raises_unavailable(self) -> None:
        provider = EchoLLMProvider()
        request = _make_request(prompt_id="ghost")
        with pytest.raises(LLMProviderUnavailableError) as exc_info:
            await provider.call(request)
        assert exc_info.value.provider == "echo"

    @pytest.mark.asyncio
    async def test_token_counts_are_deterministic(self) -> None:
        provider = EchoLLMProvider()
        provider.register_canned("demo_v1", {"answer": "x" * 200})
        req = _make_request(prompt_id="demo_v1")
        first = await provider.call(req)
        second = await provider.call(req)
        assert first.prompt_tokens == second.prompt_tokens
        assert first.completion_tokens == second.completion_tokens
        assert first.usd_cost == second.usd_cost

    @pytest.mark.asyncio
    async def test_cost_increases_with_completion_size(self) -> None:
        small = EchoLLMProvider()
        large = EchoLLMProvider()
        small.register_canned("demo_v1", {"x": "a"})
        large.register_canned("demo_v1", {"x": "a" * 4096})
        req = _make_request(prompt_id="demo_v1")
        small_resp = await small.call(req)
        large_resp = await large.call(req)
        assert large_resp.usd_cost > small_resp.usd_cost

    def test_register_canned_rejects_empty_prompt_id(self) -> None:
        provider = EchoLLMProvider()
        with pytest.raises(ValueError):
            provider.register_canned("", {"x": 1})

    def test_register_canned_rejects_non_string_non_dict(self) -> None:
        provider = EchoLLMProvider()
        with pytest.raises(TypeError):
            provider.register_canned("demo_v1", 42)  # type: ignore[arg-type]

    def test_has_registered_prompt(self) -> None:
        provider = EchoLLMProvider()
        provider.register_canned("demo_v1", {"x": 1})
        assert provider.has("demo_v1") is True
        assert provider.has("ghost") is False

    def test_satisfies_protocol(self) -> None:
        provider = EchoLLMProvider()
        assert isinstance(provider, LLMProvider)


class TestOpenAILLMProvider:
    @pytest.mark.asyncio
    async def test_no_api_key_raises_unavailable(self) -> None:
        provider = OpenAILLMProvider(api_key=None)
        request = _make_request()
        with pytest.raises(LLMProviderUnavailableError) as exc_info:
            await provider.call(request)
        assert exc_info.value.provider == "openai"
        assert "OPENAI_API_KEY" in exc_info.value.reason

    @pytest.mark.asyncio
    async def test_with_api_key_real_call_is_not_implemented(self) -> None:
        provider = OpenAILLMProvider(api_key="sk-fake")
        request = _make_request()
        with pytest.raises(NotImplementedError) as exc_info:
            await provider.call(request)
        assert "out of" in str(exc_info.value).lower()

    def test_api_key_present_property(self) -> None:
        assert OpenAILLMProvider(api_key=None).api_key_present is False
        assert OpenAILLMProvider(api_key="sk-x").api_key_present is True

    def test_base_url_property(self) -> None:
        provider = OpenAILLMProvider(api_key="sk-x", base_url="https://example.com/v1")
        assert provider.base_url == "https://example.com/v1"

    def test_satisfies_protocol(self) -> None:
        provider = OpenAILLMProvider(api_key=None)
        assert isinstance(provider, LLMProvider)
