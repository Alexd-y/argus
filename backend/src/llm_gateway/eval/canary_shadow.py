"""Canary and Shadow Evaluation — test new models without production impact.

Canary: route a fraction of traffic to new model, compare results.
Shadow: run new model in parallel, log diff without affecting user.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EvalResult:
    id: str = ""
    model_a: str = ""         # production model
    model_b: str = ""         # candidate model
    prompt_hash: str = ""
    response_a: str = ""
    response_b: str = ""
    tokens_a: int = 0
    tokens_b: int = 0
    latency_a_ms: int = 0
    latency_b_ms: int = 0
    verdict: str = ""         # better | same | worse | error
    score_delta: float = 0.0  # positive = B better
    error_b: str = ""


class CanaryRouter:
    """Routes a configurable fraction of requests to candidate model."""

    def __init__(self, canary_ratio: float = 0.05) -> None:
        self._ratio = max(0.0, min(1.0, canary_ratio))

    def should_canary(self, prompt: str) -> bool:
        h = int(hashlib.md5(prompt.encode()).hexdigest(), 16)
        return (h % 10000) / 10000.0 < self._ratio


class ShadowEvaluator:
    """Runs candidate model in parallel, compares output."""

    def __init__(self, candidate_model: str = "", candidate_url: str = "") -> None:
        self._model = candidate_model
        self._url = candidate_url
        self._results: list[EvalResult] = []

    async def shadow_call(
        self,
        messages: list[dict[str, str]],
        production_response: str,
        *,
        temperature: float = 0.2,
    ) -> EvalResult | None:
        if not self._url:
            return None

        result = EvalResult(
            id=hashlib.blake2b(str(time.time()).encode(), digest_size=8).hexdigest(),
            model_a="production", model_b=self._model,
            prompt_hash=hashlib.blake2b(
                json.dumps(messages).encode(), digest_size=12,
            ).hexdigest(),
            response_a=production_response,
            tokens_a=len(production_response.split()),
        )

        import httpx
        try:
            start = time.monotonic()
            payload = {
                "model": self._model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": 2000,
            }
            async with httpx.AsyncClient(timeout=120.0) as client:
                resp = await client.post(
                    f"{self._url}/v1/chat/completions",
                    json=payload,
                )
                resp.raise_for_status()
                data = resp.json()

            result.latency_b_ms = int((time.monotonic() - start) * 1000)
            content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
            result.response_b = content
            result.tokens_b = len(content.split())
            result.score_delta = _compare_responses(production_response, content)
            result.verdict = "better" if result.score_delta > 0.1 else "same" if result.score_delta > -0.1 else "worse"
        except Exception as exc:
            result.error_b = str(exc)
            result.verdict = "error"

        self._results.append(result)
        return result

    def summary(self) -> dict[str, Any]:
        total = len(self._results)
        if total == 0:
            return {"total": 0}
        better = sum(1 for r in self._results if r.verdict == "better")
        same = sum(1 for r in self._results if r.verdict == "same")
        worse = sum(1 for r in self._results if r.verdict == "worse")
        errors = sum(1 for r in self._results if r.verdict == "error")
        avg_delta = sum(r.score_delta for r in self._results if r.verdict != "error") / max(total - errors, 1)

        return {
            "total": total,
            "better": better,
            "same": same,
            "worse": worse,
            "errors": errors,
            "better_rate": round(better / total, 3),
            "avg_score_delta": round(avg_delta, 3),
            "candidate_model": self._model,
        }


def _compare_responses(a: str, b: str) -> float:
    if not a or not b:
        return -1.0 if b else 0.0
    a_words = set(a.lower().split())
    b_words = set(b.lower().split())
    if not a_words:
        return 0.0
    overlap = len(a_words & b_words) / len(a_words)
    return overlap - 0.7  # baseline: 70% overlap = "same"
