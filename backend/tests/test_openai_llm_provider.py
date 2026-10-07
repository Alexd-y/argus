"""P1 — OpenAILLMProvider real HTTP integration (replaces the NotImplementedError stub)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from src.llm_orchestrator.llm_provider import (
    LLMProviderUnavailableError,
    LLMRequest,
    OpenAILLMProvider,
    ResponseFormat,
)


def _req(response_format: ResponseFormat = ResponseFormat.JSON_OBJECT) -> LLMRequest:
    return LLMRequest(
        correlation_id=uuid4(),
        model_id="gpt-x",
        prompt_id="p1",
        system_prompt="sys",
        user_prompt="hi",
        max_tokens=256,
        temperature=0.0,
        response_format=response_format,
    )


class _FakeResp:
    def __init__(self, status: int, payload: dict) -> None:
        self.status_code = status
        self._payload = payload

    def json(self) -> dict:
        return self._payload


class _FakeClient:
    def __init__(self, resp: _FakeResp | None = None, exc: Exception | None = None) -> None:
        self._resp = resp
        self._exc = exc

    async def __aenter__(self) -> _FakeClient:
        return self

    async def __aexit__(self, *_a) -> bool:
        return False

    async def post(self, *_a, **_k) -> _FakeResp:
        if self._exc is not None:
            raise self._exc
        assert self._resp is not None
        return self._resp


def _patch_httpx(monkeypatch, client: _FakeClient) -> None:
    import httpx

    monkeypatch.setattr(httpx, "AsyncClient", lambda *a, **k: client, raising=True)


@pytest.mark.asyncio
async def test_missing_api_key_unavailable() -> None:
    with pytest.raises(LLMProviderUnavailableError):
        await OpenAILLMProvider(api_key=None).call(_req())


@pytest.mark.asyncio
async def test_successful_call_parses_and_costs(monkeypatch) -> None:
    payload = {
        "choices": [{"message": {"content": '{"ok": true}'}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }
    _patch_httpx(monkeypatch, _FakeClient(resp=_FakeResp(200, payload)))

    provider = OpenAILLMProvider(
        api_key="sk-test",
        price_input_per_million_usd=1.0,
        price_output_per_million_usd=2.0,
    )
    resp = await provider.call(_req())

    assert resp.content == '{"ok": true}'
    assert resp.parsed_json == {"ok": True}
    assert resp.prompt_tokens == 10
    assert resp.completion_tokens == 5
    assert resp.finish_reason == "stop"
    assert resp.usd_cost == pytest.approx(2e-5)


@pytest.mark.asyncio
async def test_function_call_finish_mapped_to_tool_calls(monkeypatch) -> None:
    payload = {
        "choices": [{"message": {"content": "{}"}, "finish_reason": "function_call"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1},
    }
    _patch_httpx(monkeypatch, _FakeClient(resp=_FakeResp(200, payload)))
    resp = await OpenAILLMProvider(api_key="sk").call(_req())
    assert resp.finish_reason == "tool_calls"  # closed taxonomy mapping


@pytest.mark.asyncio
async def test_non_200_is_unavailable(monkeypatch) -> None:
    _patch_httpx(monkeypatch, _FakeClient(resp=_FakeResp(500, {})))
    with pytest.raises(LLMProviderUnavailableError):
        await OpenAILLMProvider(api_key="sk").call(_req())


@pytest.mark.asyncio
async def test_transport_error_is_unavailable_not_notimplemented(monkeypatch) -> None:
    _patch_httpx(monkeypatch, _FakeClient(exc=RuntimeError("conn reset")))
    with pytest.raises(LLMProviderUnavailableError):
        await OpenAILLMProvider(api_key="sk").call(_req())


@pytest.mark.asyncio
async def test_text_format_leaves_parsed_json_none(monkeypatch) -> None:
    payload = {
        "choices": [{"message": {"content": "plain narrative"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 2},
    }
    _patch_httpx(monkeypatch, _FakeClient(resp=_FakeResp(200, payload)))
    resp = await OpenAILLMProvider(api_key="sk").call(_req(ResponseFormat.TEXT))
    assert resp.content == "plain narrative"
    assert resp.parsed_json is None
