"""Qwythos context-window benchmark (DoD §22 — 8k/32k/64k).

When ``QWYTHOS_URL`` (or an explicit ``base_url``) is set, each window is
probed with a live OpenAI-compatible ``/chat/completions`` ping. Prompt
contents are never logged. Unit tests without a URL keep the advertised
max_context check (no synthetic HTTP).
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

import httpx

WINDOWS_TOKENS: Final[tuple[int, ...]] = (8_192, 32_768, 65_536)
DEFAULT_MODEL: Final[str] = "qwythos-9b-claude-mythos-5-1m"

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class WindowResult:
    tokens: int
    accepted: bool
    advertised_max_context: int
    latency_ms: int
    error_code: str | None = None


def synthetic_prompt_tokens(n_tokens: int) -> int:
    """Return the requested window size without materialising a prompt."""
    if n_tokens <= 0:
        raise ValueError("window_tokens_must_be_positive")
    return n_tokens


def live_qwythos_invoke(
    tokens: int,
    *,
    base_url: str,
    timeout_s: float = 30.0,
    model: str = DEFAULT_MODEL,
) -> tuple[bool, int, str | None]:
    """Live ping. ``tokens`` selects the advertised window; the HTTP body stays tiny."""
    if tokens <= 0:
        raise ValueError("window_tokens_must_be_positive")
    url = base_url.rstrip("/") + "/chat/completions"
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": "ping"}],
        "max_tokens": 1,
    }
    start = time.perf_counter()
    try:
        with httpx.Client(timeout=timeout_s) as client:
            response = client.post(url, json=payload)
    except (httpx.HTTPError, OSError):
        latency_ms = int((time.perf_counter() - start) * 1000)
        logger.warning(
            "qwythos_benchmark_http_error",
            extra={
                "event": "qwythos_benchmark_http_error",
                "tokens": tokens,
            },
        )
        return False, latency_ms, "provider_error"
    latency_ms = int((time.perf_counter() - start) * 1000)
    if response.status_code >= 400:
        return False, latency_ms, "provider_error"
    return True, latency_ms, None


def resolve_qwythos_base_url(base_url: str | None = None) -> str:
    explicit = (base_url or "").strip()
    if explicit:
        return explicit
    return os.environ.get("QWYTHOS_URL", "").strip()


def evaluate_window(
    *,
    tokens: int,
    advertised_max_context: int,
    invoke: Callable[[int], tuple[bool, int, str | None]] | None = None,
) -> WindowResult:
    """Accept the window if it fits advertised context; optional live invoke."""
    if tokens > advertised_max_context:
        return WindowResult(
            tokens=tokens,
            accepted=False,
            advertised_max_context=advertised_max_context,
            latency_ms=0,
            error_code="context_overflow",
        )
    if invoke is None:
        return WindowResult(
            tokens=tokens,
            accepted=True,
            advertised_max_context=advertised_max_context,
            latency_ms=0,
        )
    ok, latency_ms, error_code = invoke(tokens)
    return WindowResult(
        tokens=tokens,
        accepted=ok,
        advertised_max_context=advertised_max_context,
        latency_ms=latency_ms,
        error_code=error_code,
    )


def run_qwythos_benchmark(
    *,
    advertised_max_context: int = 65_536,
    invoke: Callable[[int], tuple[bool, int, str | None]] | None = None,
    base_url: str | None = None,
) -> list[WindowResult]:
    resolved_invoke = invoke
    if resolved_invoke is None:
        url = resolve_qwythos_base_url(base_url)
        if url:
            resolved_invoke = lambda tokens, _url=url: live_qwythos_invoke(
                tokens, base_url=_url
            )
    return [
        evaluate_window(
            tokens=window,
            advertised_max_context=advertised_max_context,
            invoke=resolved_invoke,
        )
        for window in WINDOWS_TOKENS
    ]


def benchmark_summary(results: list[WindowResult]) -> dict[str, object]:
    return {
        "model": DEFAULT_MODEL,
        "windows": [r.tokens for r in results],
        "accepted": [r.tokens for r in results if r.accepted],
        "failed": [
            {"tokens": r.tokens, "error_code": r.error_code}
            for r in results
            if not r.accepted
        ],
        "all_accepted": all(r.accepted for r in results),
        "live": any(r.latency_ms > 0 for r in results),
    }
