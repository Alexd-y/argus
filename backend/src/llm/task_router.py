"""Task-based LLM routing — maps task types to optimal provider/model/params."""

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx

from src.llm.adapters import _get_key
from src.llm.errors import LLMAllProvidersFailedError

logger = logging.getLogger(__name__)


class LLMTask(Enum):
    EXECUTIVE_SUMMARY = "executive_summary"
    THREAT_MODELING = "threat_modeling"
    EXPLOIT_GENERATION = "exploit_generation"
    VALIDATION_ONESHOT = "validation_oneshot"
    REMEDIATION_PLAN = "remediation_plan"
    ZERO_DAY_ANALYSIS = "zero_day_analysis"
    DEDUP_ANALYSIS = "dedup_analysis"
    PERPLEXITY_OSINT = "perplexity_osint"
    REPORT_SECTION = "report_section"
    ORCHESTRATION = "orchestration"
    POC_GENERATION = "poc_generation"
    COST_SUMMARY = "cost_summary"


@dataclass(frozen=True)
class LLMRoute:
    provider_env_key: str
    base_url: str
    model: str
    fallback_env_key: str | None = None
    fallback_base_url: str | None = None
    fallback_model: str | None = None
    max_tokens: int = 1500
    temperature: float = 0.3


@dataclass
class LLMTaskResponse:
    text: str
    provider: str
    model: str
    prompt_tokens: int
    completion_tokens: int


_OVERRIDE_MAP: dict[str, tuple[str, str, str]] = {
    "deepseek": ("DEEPSEEK_API_KEY", "https://api.deepseek.com", "deepseek-chat"),
    "openai": ("OPENAI_API_KEY", "https://api.openai.com", "gpt-4o-mini"),
    "openrouter": ("OPENROUTER_API_KEY", "https://openrouter.ai/api", "openai/gpt-4o-mini"),
    "kimi": ("KIMI_API_KEY", "https://api.moonshot.cn", "moonshot-v1-8k"),
    "perplexity": ("PERPLEXITY_API_KEY", "https://api.perplexity.ai", "sonar"),
}

ROUTING_TABLE: dict[LLMTask, LLMRoute] = {
    LLMTask.EXECUTIVE_SUMMARY: LLMRoute(
        provider_env_key="OPENROUTER_API_KEY",
        base_url="https://openrouter.ai/api",
        model="anthropic/claude-3.5-sonnet",
        fallback_env_key="OPENAI_API_KEY",
        fallback_base_url="https://api.openai.com",
        fallback_model="gpt-4o",
        max_tokens=1500,
        temperature=0.3,
    ),
    LLMTask.THREAT_MODELING: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-reasoner",
        fallback_env_key="OPENROUTER_API_KEY",
        fallback_base_url="https://openrouter.ai/api",
        fallback_model="anthropic/claude-3.5-sonnet",
        max_tokens=2000,
        temperature=0.4,
    ),
    LLMTask.EXPLOIT_GENERATION: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        fallback_env_key="OPENAI_API_KEY",
        fallback_base_url="https://api.openai.com",
        fallback_model="gpt-4o",
        max_tokens=2000,
        temperature=0.1,
    ),
    LLMTask.VALIDATION_ONESHOT: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        fallback_env_key="OPENROUTER_API_KEY",
        fallback_base_url="https://openrouter.ai/api",
        fallback_model="meta-llama/llama-3.1-70b-instruct",
        max_tokens=800,
        temperature=0.1,
    ),
    LLMTask.REMEDIATION_PLAN: LLMRoute(
        provider_env_key="OPENAI_API_KEY",
        base_url="https://api.openai.com",
        model="gpt-4o-mini",
        fallback_env_key="DEEPSEEK_API_KEY",
        fallback_base_url="https://api.deepseek.com",
        fallback_model="deepseek-chat",
        max_tokens=2000,
        temperature=0.2,
    ),
    LLMTask.ZERO_DAY_ANALYSIS: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-reasoner",
        fallback_env_key="OPENROUTER_API_KEY",
        fallback_base_url="https://openrouter.ai/api",
        fallback_model="anthropic/claude-3.5-sonnet",
        max_tokens=1500,
        temperature=0.5,
    ),
    LLMTask.DEDUP_ANALYSIS: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        fallback_env_key="OPENAI_API_KEY",
        fallback_base_url="https://api.openai.com",
        fallback_model="gpt-4o-mini",
        max_tokens=500,
        temperature=0.0,
    ),
    LLMTask.PERPLEXITY_OSINT: LLMRoute(
        provider_env_key="PERPLEXITY_API_KEY",
        base_url="https://api.perplexity.ai",
        model="sonar-pro",
        fallback_env_key="PERPLEXITY_API_KEY",
        fallback_base_url="https://api.perplexity.ai",
        fallback_model="sonar",
        max_tokens=1000,
        temperature=0.2,
    ),
    LLMTask.REPORT_SECTION: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        fallback_env_key="OPENAI_API_KEY",
        fallback_base_url="https://api.openai.com",
        fallback_model="gpt-4o-mini",
        max_tokens=2000,
        temperature=0.3,
    ),
    LLMTask.ORCHESTRATION: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        fallback_env_key="OPENAI_API_KEY",
        fallback_base_url="https://api.openai.com",
        fallback_model="gpt-4o-mini",
        max_tokens=2000,
        temperature=0.3,
    ),
    LLMTask.POC_GENERATION: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        fallback_env_key="OPENAI_API_KEY",
        fallback_base_url="https://api.openai.com",
        fallback_model="gpt-4o",
        max_tokens=2000,
        temperature=0.1,
    ),
    LLMTask.COST_SUMMARY: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        fallback_env_key="OPENAI_API_KEY",
        fallback_base_url="https://api.openai.com",
        fallback_model="gpt-4o-mini",
        max_tokens=500,
        temperature=0.2,
    ),
}


async def _call_route(
    route_env_key: str,
    route_base_url: str,
    model: str,
    prompt: str,
    system_prompt: str | None,
    max_tokens: int,
    temperature: float,
) -> LLMTaskResponse:
    """Execute a single provider call, returning structured response with token usage."""
    key = _get_key(route_env_key)
    if not key:
        raise RuntimeError(f"Provider not configured: {route_env_key}")

    messages: list[dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": prompt})

    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    url = f"{route_base_url.rstrip('/')}/v1/chat/completions"
    headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}

    async with httpx.AsyncClient(timeout=120.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    choices = data.get("choices", [])
    if not choices:
        raise ValueError("Empty response from LLM")

    content = choices[0].get("message", {}).get("content", "")
    usage = data.get("usage", {})

    return LLMTaskResponse(
        text=(content or "").strip(),
        provider=route_env_key,
        model=model,
        prompt_tokens=usage.get("prompt_tokens", 0),
        completion_tokens=usage.get("completion_tokens", 0),
    )


def _build_attempts(route: LLMRoute) -> list[tuple[str, str, str]]:
    """Build ordered list of (env_key, base_url, model) attempts with optional override."""
    attempts: list[tuple[str, str, str]] = []

    primary_override = (os.environ.get("LLM_PRIMARY_PROVIDER") or "").strip().lower()
    if primary_override and primary_override in _OVERRIDE_MAP:
        ov = _OVERRIDE_MAP[primary_override]
        attempts.append(ov)

    attempts.append((route.provider_env_key, route.base_url, route.model))

    if route.fallback_env_key and route.fallback_base_url and route.fallback_model:
        attempts.append(
            (route.fallback_env_key, route.fallback_base_url, route.fallback_model)
        )

    return attempts


async def call_llm_for_task(
    task: LLMTask,
    prompt: str,
    *,
    system_prompt: str | None = None,
) -> LLMTaskResponse:
    """Route LLM call based on task type with primary → fallback chain.

    Uses routing table to pick optimal provider/model per task.
    Respects ``LLM_PRIMARY_PROVIDER`` env override (prepends that provider
    to the attempt list regardless of the routing table).
    """
    route = ROUTING_TABLE.get(task)
    if route is None:
        route = ROUTING_TABLE[LLMTask.ORCHESTRATION]

    attempts = _build_attempts(route)

    last_error: Exception | None = None
    for env_key, base_url, model in attempts:
        if not _get_key(env_key):
            continue
        try:
            return await _call_route(
                route_env_key=env_key,
                route_base_url=base_url,
                model=model,
                prompt=prompt,
                system_prompt=system_prompt,
                max_tokens=route.max_tokens,
                temperature=route.temperature,
            )
        except Exception as e:
            last_error = e
            logger.warning(
                "Task LLM route failed, trying fallback",
                extra={
                    "task": task.value,
                    "provider": env_key,
                    "model": model,
                    "error_type": type(e).__name__,
                },
            )

    raise LLMAllProvidersFailedError(
        f"All providers failed for task {task.value}: "
        f"{type(last_error).__name__ if last_error else 'no providers configured'}"
    )
