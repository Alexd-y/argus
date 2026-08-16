"""Task-based LLM routing — maps task types to optimal provider/model/params.

Extended with 3-tier model routing (small/medium/large) and confidence-based
escalation: tasks start on cheap models and escalate to expensive ones when
confidence is low, inspired by Shannon's tiered approach but adapted for
ARGUS's multi-provider architecture.
"""

import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any

import httpx

from src.llm.adapters import _get_key
from src.llm.errors import LLMAllProvidersFailedError

logger = logging.getLogger(__name__)


class LLMTier(Enum):
    """Model tiers for cost-aware routing with escalation.

    SMALL: Fast, cheap models for summarization, classification, dedup
    MEDIUM: Balanced models for analysis, threat modeling, report generation
    LARGE: Expensive, high-reasoning models for exploit generation, zero-day
    """

    SMALL = "small"
    MEDIUM = "medium"
    LARGE = "large"


class LLMTask(Enum):
    EXECUTIVE_SUMMARY = "executive_summary"
    THREAT_MODELING = "threat_modeling"
    VULN_ANALYSIS = "vuln_analysis"
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
    QUICK_PLANNER = "quick_planner"
    QUICK_FINGERPRINT = "quick_fingerprint"
    QUICK_TRIAGE = "quick_triage"
    QUICK_CRITIC = "quick_critic"
    QUICK_REPORTER = "quick_reporter"


_TASK_TO_ROLE: dict[LLMTask, str] = {
    LLMTask.ORCHESTRATION: "planner",
    LLMTask.THREAT_MODELING: "planner",
    LLMTask.VULN_ANALYSIS: "planner",
    LLMTask.VALIDATION_ONESHOT: "planner",
    LLMTask.DEDUP_ANALYSIS: "planner",
    LLMTask.ZERO_DAY_ANALYSIS: "planner",
    LLMTask.POC_GENERATION: "code",
    LLMTask.EXPLOIT_GENERATION: "code",
    LLMTask.PERPLEXITY_OSINT: "osint",
    LLMTask.REPORT_SECTION: "report",
    LLMTask.EXECUTIVE_SUMMARY: "report",
    LLMTask.REMEDIATION_PLAN: "report",
    LLMTask.COST_SUMMARY: "report",
    LLMTask.QUICK_PLANNER: "planner",
    LLMTask.QUICK_FINGERPRINT: "planner",
    LLMTask.QUICK_TRIAGE: "planner",
    LLMTask.QUICK_CRITIC: "planner",
    LLMTask.QUICK_REPORTER: "report",
}


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

# Sentinel base_url for Google Gemini (OpenAI-compatible path not used).
_GEMINI_ROUTE_SENTINEL = "__argus_gemini__"

# Universal fallback order after task-specific primaries from ROUTING_TABLE.
# Missing keys are skipped; HTTP/auth errors try the next provider (see call_llm_for_task).
_GLOBAL_LLM_FALLBACK_CHAIN: tuple[tuple[str, str, str], ...] = (
    ("OPENROUTER_API_KEY", "https://openrouter.ai/api", "openai/gpt-4o-mini"),
    ("KIMI_API_KEY", "https://api.moonshot.cn", "moonshot-v1-8k"),
    ("PERPLEXITY_API_KEY", "https://api.perplexity.ai", "sonar"),
    ("OPENAI_API_KEY", "https://api.openai.com", "gpt-4o-mini"),
    ("DEEPSEEK_API_KEY", "https://api.deepseek.com", "deepseek-chat"),
    ("GOOGLE_API_KEY", _GEMINI_ROUTE_SENTINEL, "gemini-1.5-flash"),
)


def _merge_route_with_global_chain(route_attempts: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """Append universal fallbacks without duplicating env keys already used by the route.

    Route-defined attempts may include the same env key twice (e.g. Perplexity sonar-pro → sonar);
    those are preserved. Global entries are only added for keys that never appear in the route list.
    """
    keys_in_route = {env_key for env_key, _, _ in route_attempts}
    out = list(route_attempts)
    for entry in _GLOBAL_LLM_FALLBACK_CHAIN:
        env_key = entry[0]
        if env_key in keys_in_route:
            continue
        keys_in_route.add(env_key)
        out.append(entry)
    return out

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
    LLMTask.VULN_ANALYSIS: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-reasoner",
        fallback_env_key="OPENROUTER_API_KEY",
        fallback_base_url="https://openrouter.ai/api",
        fallback_model="anthropic/claude-3.5-sonnet",
        max_tokens=2000,
        temperature=0.3,
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
    LLMTask.QUICK_PLANNER: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        max_tokens=4096,
        temperature=0.2,
    ),
    LLMTask.QUICK_FINGERPRINT: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        max_tokens=2048,
        temperature=0.0,
    ),
    LLMTask.QUICK_TRIAGE: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        max_tokens=2048,
        temperature=0.0,
    ),
    LLMTask.QUICK_CRITIC: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        max_tokens=2048,
        temperature=0.1,
    ),
    LLMTask.QUICK_REPORTER: LLMRoute(
        provider_env_key="DEEPSEEK_API_KEY",
        base_url="https://api.deepseek.com",
        model="deepseek-chat",
        fallback_env_key="OPENAI_API_KEY",
        fallback_base_url="https://api.openai.com",
        fallback_model="gpt-4o-mini",
        max_tokens=4096,
        temperature=0.2,
    ),
}

# --- 3-Tier Model Routing with Escalation ---

TASK_TIERS: dict[LLMTask, dict[str, Any]] = {
    LLMTask.EXECUTIVE_SUMMARY: {"tier": LLMTier.SMALL, "escalation_threshold": 0.5},
    LLMTask.THREAT_MODELING: {"tier": LLMTier.MEDIUM, "escalation_threshold": 0.6},
    LLMTask.VULN_ANALYSIS: {"tier": LLMTier.MEDIUM, "escalation_threshold": 0.6},
    LLMTask.EXPLOIT_GENERATION: {"tier": LLMTier.LARGE, "escalation_threshold": 0.7},
    LLMTask.VALIDATION_ONESHOT: {"tier": LLMTier.SMALL, "escalation_threshold": 0.5},
    LLMTask.REMEDIATION_PLAN: {"tier": LLMTier.SMALL, "escalation_threshold": 0.5},
    LLMTask.ZERO_DAY_ANALYSIS: {"tier": LLMTier.LARGE, "escalation_threshold": 0.8},
    LLMTask.DEDUP_ANALYSIS: {"tier": LLMTier.SMALL, "escalation_threshold": 0.4},
    LLMTask.PERPLEXITY_OSINT: {"tier": LLMTier.MEDIUM, "escalation_threshold": 0.7},
    LLMTask.REPORT_SECTION: {"tier": LLMTier.MEDIUM, "escalation_threshold": 0.6},
    LLMTask.ORCHESTRATION: {"tier": LLMTier.MEDIUM, "escalation_threshold": 0.6},
    LLMTask.POC_GENERATION: {"tier": LLMTier.LARGE, "escalation_threshold": 0.7},
    LLMTask.COST_SUMMARY: {"tier": LLMTier.SMALL, "escalation_threshold": 0.3},
    LLMTask.QUICK_PLANNER: {"tier": LLMTier.MEDIUM, "escalation_threshold": 0.6},
    LLMTask.QUICK_FINGERPRINT: {"tier": LLMTier.SMALL, "escalation_threshold": 0.4},
    LLMTask.QUICK_TRIAGE: {"tier": LLMTier.SMALL, "escalation_threshold": 0.4},
    LLMTask.QUICK_CRITIC: {"tier": LLMTier.MEDIUM, "escalation_threshold": 0.6},
    LLMTask.QUICK_REPORTER: {"tier": LLMTier.MEDIUM, "escalation_threshold": 0.5},
}

TIER_MODELS: dict[LLMTier, dict[str, str]] = {
    LLMTier.SMALL: {
        "default_provider": "DEEPSEEK_API_KEY",
        "default_model": "deepseek-chat",
        "escalation_provider": "OPENAI_API_KEY",
        "escalation_model": "gpt-4o-mini",
    },
    LLMTier.MEDIUM: {
        "default_provider": "OPENAI_API_KEY",
        "default_model": "gpt-4o",
        "escalation_provider": "OPENROUTER_API_KEY",
        "escalation_model": "anthropic/claude-sonnet-4-20250514",
    },
    LLMTier.LARGE: {
        "default_provider": "OPENROUTER_API_KEY",
        "default_model": "anthropic/claude-opus-4-20250514",
        "escalation_provider": "OPENAI_API_KEY",
        "escalation_model": "o3-pro",
    },
}

# Confidence threshold below which we escalate to the next tier
ESCALATION_CONFIDENCE_THRESHOLD = 0.7


async def _call_gemini_route(
    *,
    prompt: str,
    system_prompt: str | None,
    model: str,
) -> LLMTaskResponse:
    """Gemini uses generateContent, not OpenAI-compatible chat completions."""
    from src.llm.adapters import GeminiAdapter

    adapter = GeminiAdapter()
    text = await adapter.call(prompt, system_prompt=system_prompt, model=model)
    return LLMTaskResponse(
        text=text,
        provider="GOOGLE_API_KEY",
        model=model,
        prompt_tokens=0,
        completion_tokens=0,
    )


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

    attempts = _merge_route_with_global_chain(_build_attempts(route))

    last_error: Exception | None = None
    skipped_no_key: list[str] = []
    seen_skip: set[str] = set()
    for env_key, base_url, model in attempts:
        if not _get_key(env_key):
            if env_key not in seen_skip:
                seen_skip.add(env_key)
                skipped_no_key.append(env_key)
            continue
        try:
            if base_url == _GEMINI_ROUTE_SENTINEL:
                return await _call_gemini_route(
                    prompt=prompt,
                    system_prompt=system_prompt,
                    model=model,
                )
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

    msg = (
        f"All providers failed for task {task.value}: "
        f"{type(last_error).__name__ if last_error else 'no providers configured'}"
    )
    if skipped_no_key:
        msg += ". Skipped (no or empty API key): " + ", ".join(skipped_no_key)
    raise LLMAllProvidersFailedError(msg)


def get_tier_for_task(task: LLMTask) -> dict[str, Any]:
    """Return tier config for a task from TASK_TIERS (for reporting/logging)."""
    return TASK_TIERS.get(task, {"tier": LLMTier.MEDIUM, "escalation_threshold": 0.7})


def get_model_for_tier(tier: LLMTier, provider: str | None = None) -> dict[str, str]:
    """Return provider/model mapping for a given tier.

    When ``provider`` is specified, returns only that provider's model.
    Otherwise returns all providers for the tier.
    """
    tier_models = TIER_MODELS.get(tier, TIER_MODELS[LLMTier.MEDIUM])
    if provider:
        model_name = tier_models.get(provider)
        if model_name:
            return {provider: model_name}
    return tier_models


class LLMTierEscalationResult:
    """Result of tier-based LLM escalation check."""

    __slots__ = ("escalated", "original_tier", "escalated_tier", "confidence", "threshold")

    def __init__(
        self,
        escalated: bool,
        original_tier: LLMTier,
        escalated_tier: LLMTier | None = None,
        confidence: float = 1.0,
        threshold: float = 0.7,
    ) -> None:
        self.escalated = escalated
        self.original_tier = original_tier
        self.escalated_tier = escalated_tier
        self.confidence = confidence
        self.threshold = threshold


def check_tier_escalation(
    task: LLMTask,
    confidence: float,
) -> LLMTierEscalationResult:
    """Check if a task result should be escalated to a higher tier.

    When confidence is below the task's escalation_threshold,
    the task should be re-run on the next higher tier.

    Parameters
    ----------
    task:
        The LLM task that was executed.
    confidence:
        The confidence score of the result (0.0-1.0).

    Returns
    -------
    LLMTierEscalationResult indicating whether escalation is needed.
    """
    tier_info = TASK_TIERS.get(task, {"tier": LLMTier.MEDIUM, "escalation_threshold": 0.7})
    current_tier = tier_info["tier"]
    threshold = tier_info["escalation_threshold"]

    if confidence >= threshold:
        return LLMTierEscalationResult(
            escalated=False,
            original_tier=current_tier,
            confidence=confidence,
            threshold=threshold,
        )

    tier_order = [LLMTier.SMALL, LLMTier.MEDIUM, LLMTier.LARGE]
    current_idx = tier_order.index(current_tier)
    if current_idx >= len(tier_order) - 1:
        return LLMTierEscalationResult(
            escalated=False,
            original_tier=current_tier,
            confidence=confidence,
            threshold=threshold,
        )

    escalated_tier = tier_order[current_idx + 1]
    return LLMTierEscalationResult(
        escalated=True,
        original_tier=current_tier,
        escalated_tier=escalated_tier,
        confidence=confidence,
        threshold=threshold,
    )
