"""WRB adapter — completion clamp + prompt trim keep prompt+completion within n_ctx."""

from __future__ import annotations

from src.llm.whiterabbitneo_adapter import (
    _CHARS_PER_TOKEN,
    _MIN_PROMPT_TOKENS,
    WhiteRabbitNeoAdapter,
)


def _adapter(n_ctx: int) -> WhiteRabbitNeoAdapter:
    return WhiteRabbitNeoAdapter(base_url="http://wrb:8000/v1", max_context_tokens=n_ctx)


def test_effective_max_tokens_clamped_for_small_ctx():
    a = _adapter(4096)
    # A default 4096 completion would leave no room for the prompt at n_ctx=4096.
    eff = a._effective_max_tokens(4096)
    assert eff <= 4096 - _MIN_PROMPT_TOKENS
    # prompt floor + completion must fit the window
    assert _MIN_PROMPT_TOKENS + eff <= 4096


def test_effective_max_tokens_passthrough_for_large_ctx():
    a = _adapter(32768)
    assert a._effective_max_tokens(4096) == 4096


def test_effective_max_tokens_floor():
    a = _adapter(2048)  # min clamps to 2048
    eff = a._effective_max_tokens(4096)
    assert eff >= 1
    assert _MIN_PROMPT_TOKENS + eff <= max(2048, a._max_context_tokens)


def test_prompt_budget_positive_at_small_ctx():
    a = _adapter(4096)
    eff = a._effective_max_tokens(4096)
    budget = a._prompt_char_budget(eff)
    assert budget >= _MIN_PROMPT_TOKENS * _CHARS_PER_TOKEN
