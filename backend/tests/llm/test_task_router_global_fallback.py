"""Global LLM fallback chain: any configured provider may satisfy a task (ARGUS-LLM-fallback)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import httpx
import pytest

from src.llm.task_router import (
    _GLOBAL_LLM_FALLBACK_CHAIN,
    _merge_route_with_global_chain,
)
from src.llm.task_router import LLMTask
from src.llm.task_router import call_llm_for_task


def test_global_chain_order_matches_product_requirement() -> None:
    keys = [t[0] for t in _GLOBAL_LLM_FALLBACK_CHAIN]
    assert keys == [
        "OPENROUTER_API_KEY",
        "KIMI_API_KEY",
        "PERPLEXITY_API_KEY",
        "OPENAI_API_KEY",
        "DEEPSEEK_API_KEY",
        "GOOGLE_API_KEY",
    ]


def test_merge_preserves_route_multi_same_env() -> None:
    route_attempts = [
        ("PERPLEXITY_API_KEY", "https://api.perplexity.ai", "sonar-pro"),
        ("PERPLEXITY_API_KEY", "https://api.perplexity.ai", "sonar"),
    ]
    merged = _merge_route_with_global_chain(route_attempts)
    assert merged[:2] == route_attempts
    assert not any(
        e[0] == "PERPLEXITY_API_KEY" for e in merged[2:]
    ), "global Perplexity must not duplicate route Perplexity"


def test_merge_appends_openrouter_when_route_only_deepseek_openai() -> None:
    route_attempts = [
        ("DEEPSEEK_API_KEY", "https://api.deepseek.com", "deepseek-chat"),
        ("OPENAI_API_KEY", "https://api.openai.com", "gpt-4o-mini"),
    ]
    merged = _merge_route_with_global_chain(route_attempts)
    assert merged[:2] == route_attempts
    assert merged[2][0] == "OPENROUTER_API_KEY"


@pytest.mark.asyncio
async def test_call_skips_empty_env_and_succeeds_on_later_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("KIMI_API_KEY", raising=False)
    monkeypatch.delenv("PERPLEXITY_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setenv("DEEPSEEK_API_KEY", "sk-bad")  # present but will fail fast

    async def fake_call_route(**kwargs: object) -> object:
        from src.llm.task_router import LLMTaskResponse

        env_key = kwargs["route_env_key"]
        if env_key == "DEEPSEEK_API_KEY":
            req = httpx.Request("POST", "https://api.deepseek.com/v1/chat/completions")
            resp = httpx.Response(401, request=req)
            raise httpx.HTTPStatusError("401", request=req, response=resp)
        return LLMTaskResponse(
            text="ok-from-openrouter",
            provider=str(env_key),
            model=str(kwargs["model"]),
            prompt_tokens=1,
            completion_tokens=2,
        )

    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-good")

    with patch("src.llm.task_router._call_route", new=fake_call_route):
        with patch("src.llm.task_router._call_gemini_route", new=AsyncMock()):
            resp = await call_llm_for_task(
                LLMTask.ORCHESTRATION,
                "hello",
                system_prompt="sys",
            )
    assert resp.text == "ok-from-openrouter"
    assert resp.provider == "OPENROUTER_API_KEY"


# Re-export sentinel for tests (avoid importing private name in tests package)
GEMINI_SENTINEL_FOR_TESTS = __import__(
    "src.llm.task_router", fromlist=["_GEMINI_ROUTE_SENTINEL"]
)._GEMINI_ROUTE_SENTINEL


@pytest.mark.asyncio
async def test_gemini_invoked_when_only_google_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in (
        "DEEPSEEK_API_KEY",
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "KIMI_API_KEY",
        "PERPLEXITY_API_KEY",
    ):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "fake-gemini")

    from src.llm.task_router import LLMTaskResponse

    gemini_mock = AsyncMock(
        return_value=LLMTaskResponse(
            text="gemini-ok",
            provider="GOOGLE_API_KEY",
            model="gemini-1.5-flash",
            prompt_tokens=0,
            completion_tokens=0,
        )
    )

    with patch("src.llm.task_router._call_route", new=AsyncMock(side_effect=AssertionError("openapi should not run"))):
        with patch("src.llm.task_router._call_gemini_route", new=gemini_mock):
            resp = await call_llm_for_task(LLMTask.ORCHESTRATION, "p", system_prompt=None)
    assert resp.text == "gemini-ok"
    gemini_mock.assert_awaited_once()
