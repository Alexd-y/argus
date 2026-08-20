"""Unified LLM entry point — single source of truth for all LLM calls in ARGUS.

WhiteRabbitNeo V3 7B is the primary AI for ALL pentest analysis tasks.
Cloud providers (DeepSeek, OpenAI, Perplexity) serve only as supplements
for report formatting and OSINT enrichment.

Routing logic:
  - Pentest tasks (ORCHESTRATION, THREAT_MODELING, …) → WhiteRabbitNeo ONLY.
    If WRB is unavailable OR not configured, these tasks fail closed (RuntimeError);
    cloud fallback is never permitted (local-only confidentiality invariant).
  - Report tasks (REPORT_SECTION, EXECUTIVE_SUMMARY, COST_SUMMARY) → WRB first, cloud fallback
  - OSINT tasks (PERPLEXITY_OSINT) → Perplexity directly (WRB has no internet)
  - No task specified → legacy generic router

BKL-006: eliminates the three-way split between router / task_router / llm_config.
FIX-004: integrates ScanCostTracker — every LLM call records token usage when scan_id is provided.
LLM-004/M-3: token counting via response.usage primary, tiktoken cl100k_base fallback.
AUD4-003/M-1: deprecation warning when task=None; tiktoken only as fallback.
WRB-001: WhiteRabbitNeo-first routing for all pentest analysis tasks.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import logging
import os
import time
import uuid
import warnings

import httpx

from src.core.config import settings
from src.execution_mode.metrics import increment_llm_fallback
from src.execution_mode.runtime_context import resolve_execution_mode_with_fallback
from src.governance.safety.monitor import get_safety_monitor

from src.llm.adapters import _get_key
from src.llm.phase_routing import PhaseRoute, get_phase_route
from src.llm.router import call_llm as _router_call_llm
from src.llm.gateway import get_unified_llm_gateway
from src.llm.schemas import (
    ContentClass,
    ExecutionMode,
    LlmRequest,
    LlmResponseEnvelope,
    LlmResponseStatus,
)
from src.llm.task_router import LLMTask
from src.llm.task_router import _TASK_TO_ROLE
from src.llm.task_router import call_llm_for_task as _task_router_call
from src.llm.task_router import check_tier_escalation

logger = logging.getLogger(__name__)

_SYNC_TIMEOUT_SECONDS = 1800

_tiktoken_enc = None

# WRB request concurrency — balanced for throughput vs. llama.cpp memory pressure.
_wrb_semaphore: asyncio.Semaphore | None = None
_WRB_CONCURRENCY = 3

def _get_wrb_semaphore() -> asyncio.Semaphore:
    global _wrb_semaphore
    if _wrb_semaphore is None:
        _wrb_semaphore = asyncio.Semaphore(_WRB_CONCURRENCY)
    return _wrb_semaphore

# Tasks where cloud fallback is ALLOWED (report supplements / OSINT).
# Pentest analysis tasks use WhiteRabbitNeo ONLY — no cloud fallback.
_CLOUD_FALLBACK_TASKS: frozenset[LLMTask] = frozenset({
    LLMTask.REPORT_SECTION,
    LLMTask.EXECUTIVE_SUMMARY,
    LLMTask.COST_SUMMARY,
    LLMTask.PERPLEXITY_OSINT,
})

# Tasks that PREFER a cloud model: exploit/PoC payload generation requires strict,
# valid-JSON output. The local WRB-7B frequently emits malformed payload JSON
# (`wrb_payload_generation_failed`); cloud models honour the "return ONLY JSON"
# contract far more reliably. WRB stays the engine for every analysis task.
# Behaviour is controlled by ARGUS_EXPLOIT_LLM: ``auto`` (cloud when a key exists,
# else WRB), ``cloud`` (force cloud, error if no key), ``wrb`` (legacy WRB-only).
_CLOUD_PREFERRED_TASKS: frozenset[LLMTask] = frozenset({
    LLMTask.EXPLOIT_GENERATION,
    LLMTask.POC_GENERATION,
})

_CLOUD_KEY_ENVS: tuple[str, ...] = (
    "DEEPSEEK_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "KIMI_API_KEY",
    "PERPLEXITY_API_KEY",
    "GOOGLE_API_KEY",
)

_ROLE_TO_PREFERRED_ALIAS: dict[str, str] = {
    "planner": "security_reasoner",
    "code": "code_utility",
    "report": "report_writer",
    "osint": "report_writer",
}

# Task-level overrides — distinct aliases must resolve different provider chains.
_TASK_TO_PREFERRED_ALIAS: dict[LLMTask, str] = {
    LLMTask.ORCHESTRATION: "facade_orchestrator",
    LLMTask.THREAT_MODELING: "security_reasoner",
    LLMTask.VULN_ANALYSIS: "security_reasoner",
    LLMTask.VALIDATION_ONESHOT: "security_reasoner",
    LLMTask.DEDUP_ANALYSIS: "fast_triage",
    LLMTask.ZERO_DAY_ANALYSIS: "security_reasoner",
    LLMTask.POC_GENERATION: "code_utility",
    LLMTask.EXPLOIT_GENERATION: "wrb_critic",
    LLMTask.REPORT_SECTION: "report_writer",
    LLMTask.EXECUTIVE_SUMMARY: "report_writer",
    LLMTask.REMEDIATION_PLAN: "report_writer",
    LLMTask.COST_SUMMARY: "report_writer",
    LLMTask.QUICK_PLANNER: "quick_planner",
    LLMTask.QUICK_FINGERPRINT: "quick_triage",
    LLMTask.QUICK_TRIAGE: "quick_triage",
    LLMTask.QUICK_CRITIC: "quick_critic",
    LLMTask.QUICK_REPORTER: "quick_reporter",
}

# Pack §13 prompt ids attached when a response schema is requested.
_SCHEMA_BOUND_PROMPT_IDS: dict[LLMTask, str] = {
    LLMTask.ORCHESTRATION: "scan_planner_v2",
    LLMTask.VALIDATION_ONESHOT: "wrb_security_critic_v3",
    LLMTask.QUICK_PLANNER: "quick_planner_v1",
    LLMTask.QUICK_FINGERPRINT: "quick_fingerprint_classifier_v1",
    LLMTask.QUICK_TRIAGE: "quick_finding_triage_v1",
    LLMTask.QUICK_CRITIC: "quick_security_critic_v1",
    LLMTask.QUICK_REPORTER: "quick_reporter_v1",
}

_QUICK_TASKS: frozenset[LLMTask] = frozenset(
    {
        LLMTask.QUICK_PLANNER,
        LLMTask.QUICK_FINGERPRINT,
        LLMTask.QUICK_TRIAGE,
        LLMTask.QUICK_CRITIC,
        LLMTask.QUICK_REPORTER,
    }
)
_QUICK_QWYTHOS_TASKS: frozenset[LLMTask] = frozenset(
    {LLMTask.QUICK_PLANNER, LLMTask.QUICK_REPORTER}
)
_QUICK_SMALL_TASKS: frozenset[LLMTask] = frozenset(
    {LLMTask.QUICK_FINGERPRINT, LLMTask.QUICK_TRIAGE}
)
_QUICK_DEFAULT_TIMEOUT_SEC = 30.0


def _should_use_unified_gateway(
    task: LLMTask | None,
    response_schema_id: str | None,
    use_unified: bool,
) -> bool:
    if not settings.argus_unified_llm_gateway:
        return False
    if task is None or not isinstance(task, LLMTask):
        return False
    if task == LLMTask.PERPLEXITY_OSINT:
        return False
    if task in _QUICK_TASKS:
        # Quick has its own Qwythos/WRB/small routing. Skipping the unified
        # gateway avoids prepending SYSTEM_BASE_V3 (which asks for shell/payloads).
        return False
    if use_unified or response_schema_id:
        return True
    return True


def _task_to_preferred_alias(task: LLMTask) -> str:
    override = _TASK_TO_PREFERRED_ALIAS.get(task)
    if override:
        return override
    role = _TASK_TO_ROLE.get(task, "planner")
    return _ROLE_TO_PREFERRED_ALIAS.get(role, "security_reasoner")


def _resolve_prompt_id(
    task: LLMTask,
    response_schema_id: str | None,
    prompt_id: str | None = None,
) -> str:
    explicit = (prompt_id or "").strip()
    if explicit:
        return explicit
    if response_schema_id:
        return _SCHEMA_BOUND_PROMPT_IDS.get(task, "")
    return ""


def _to_llm_execution_mode(mode: object) -> ExecutionMode:
    if isinstance(mode, ExecutionMode):
        return mode
    raw = str(getattr(mode, "value", mode)).strip().lower()
    try:
        return ExecutionMode(raw)
    except ValueError:
        return ExecutionMode.PRODUCTION


def _resolve_execution_mode(
    execution_mode: ExecutionMode | str | None,
    scan_options: dict | None = None,
    *,
    phase: str = "unknown",
    task: LLMTask | None = None,
    warn_if_missing: bool = False,
) -> ExecutionMode:
    domain_mode, missing = resolve_execution_mode_with_fallback(
        execution_mode,
        scan_options,
    )
    if not missing:
        return _to_llm_execution_mode(domain_mode)
    if execution_mode is not None and execution_mode != "":
        raw = getattr(execution_mode, "value", execution_mode)
        normalized = str(raw).strip().lower()
        logger.warning(
            "unified_gateway_unknown_execution_mode",
            extra={
                "event": "unified_gateway_unknown_execution_mode",
                "execution_mode": normalized,
            },
        )
        return ExecutionMode.PRODUCTION
    if warn_if_missing:
        logger.warning(
            "llm_execution_mode_missing",
            extra={
                "event": "llm_execution_mode_missing",
                "phase": phase,
                "task": task.value if task is not None else "none",
                "default": ExecutionMode.PRODUCTION.value,
            },
        )
    return ExecutionMode.PRODUCTION


def _resolve_content_class(
    content_class: ContentClass | str | None,
    execution_mode: ExecutionMode,
) -> ContentClass:
    if content_class is not None and content_class != "":
        if isinstance(content_class, ContentClass):
            return content_class
        raw = getattr(content_class, "value", content_class)
        try:
            return ContentClass(str(raw).strip().lower())
        except ValueError:
            logger.warning(
                "unified_gateway_unknown_content_class",
                extra={
                    "event": "unified_gateway_unknown_content_class",
                    "content_class": str(raw),
                },
            )
    if execution_mode == ExecutionMode.LAB_UNRESTRICTED:
        return ContentClass.LAB_ARTIFACT
    return ContentClass.INTERNAL


def _coerce_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _resolve_lab_cloud_allowed(
    execution_mode: ExecutionMode,
    scan_options: dict | None,
) -> bool:
    if execution_mode != ExecutionMode.LAB_UNRESTRICTED:
        return False
    if scan_options and "lab_cloud_allowed" in scan_options:
        return _coerce_bool(scan_options.get("lab_cloud_allowed"))
    return bool(settings.lab_cloud_allowed)


def _build_gateway_request(
    system_prompt: str,
    user_prompt: str,
    task: LLMTask,
    *,
    scan_id: str | None,
    phase: str,
    response_schema_id: str | None,
    tenant_id: str | None,
    engagement_id: str | None,
    execution_mode: ExecutionMode | str | None = None,
    preferred_alias: str | None = None,
    content_class: ContentClass | str | None = None,
    scan_options: dict | None = None,
    prompt_id: str | None = None,
) -> LlmRequest:
    resolved_tenant = tenant_id or settings.default_tenant_id
    resolved_engagement = engagement_id or scan_id or "unknown"
    resolved_mode = _resolve_execution_mode(
        execution_mode,
        scan_options,
        phase=phase,
        task=task,
        warn_if_missing=True,
    )
    resolved_alias = (preferred_alias or "").strip() or _task_to_preferred_alias(task)
    return LlmRequest(
        request_id=f"facade_{uuid.uuid4().hex[:16]}",
        tenant_id=resolved_tenant,
        engagement_id=resolved_engagement,
        scan_id=scan_id,
        phase=phase,
        task_type=task.value,
        execution_mode=resolved_mode,
        content_class=_resolve_content_class(content_class, resolved_mode),
        preferred_alias=resolved_alias,
        user_prompt=user_prompt,
        system_prompt=system_prompt or None,
        response_schema_id=response_schema_id,
        prompt_id=_resolve_prompt_id(task, response_schema_id, prompt_id),
        lab_cloud_allowed=_resolve_lab_cloud_allowed(resolved_mode, scan_options),
    )


def _envelope_to_text(
    envelope: LlmResponseEnvelope,
    response_schema_id: str | None,
) -> str:
    if envelope.status == LlmResponseStatus.SCHEMA_ERROR:
        raise RuntimeError(
            f"LLM response schema validation failed "
            f"(schema_id={envelope.schema_id or response_schema_id}): "
            f"{envelope.result.get('raw_text', envelope.result)}"
        )
    if envelope.status == LlmResponseStatus.PROVIDER_ERROR:
        error_code = envelope.result.get("error_code", "provider_error")
        raise RuntimeError(f"Unified LLM gateway provider error: {error_code}")
    if envelope.status != LlmResponseStatus.OK:
        raise RuntimeError(
            f"Unified LLM gateway returned non-ok status: {envelope.status}"
        )

    result = envelope.result
    if response_schema_id:
        return json.dumps(result, ensure_ascii=False)
    if isinstance(result.get("text"), str):
        return result["text"]
    return json.dumps(result, ensure_ascii=False)


async def _call_via_unified_gateway(
    system_prompt: str,
    user_prompt: str,
    task: LLMTask,
    *,
    scan_id: str | None = None,
    phase: str = "unknown",
    response_schema_id: str | None = None,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    execution_mode: ExecutionMode | str | None = None,
    preferred_alias: str | None = None,
    content_class: ContentClass | str | None = None,
    scan_options: dict | None = None,
    prompt_id: str | None = None,
) -> str:
    gateway = get_unified_llm_gateway()
    request = _build_gateway_request(
        system_prompt,
        user_prompt,
        task,
        scan_id=scan_id,
        phase=phase,
        response_schema_id=response_schema_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        execution_mode=execution_mode,
        preferred_alias=preferred_alias,
        content_class=content_class,
        scan_options=scan_options,
        prompt_id=prompt_id,
    )
    envelope = await gateway.generate(request)

    if envelope.status == LlmResponseStatus.PROVIDER_ERROR and task in _CLOUD_FALLBACK_TASKS:
        logger.info(
            "unified_gateway_provider_error_cloud_fallback",
            extra={
                "event": "unified_gateway_provider_error_cloud_fallback",
                "task": task.value,
                "phase": phase,
                "error_code": envelope.result.get("error_code", "provider_error"),
            },
        )
        return await _call_via_task_router(
            system_prompt,
            user_prompt,
            task,
            scan_id=scan_id,
            phase=phase,
        )

    if scan_id and envelope.usage:
        model_label = envelope.model or envelope.alias or "unified_gateway"
        _record_llm_cost(
            scan_id,
            phase,
            task.value,
            model_label,
            envelope.usage.input_tokens,
            envelope.usage.output_tokens,
        )
        _annotate_last_cost_record(
            scan_id,
            envelope.alias or envelope.provider,
            bool(envelope.fallback_attempts),
            envelope.usage.latency_ms,
        )

    return _envelope_to_text(envelope, response_schema_id)


def _exploit_llm_mode() -> str:
    """Resolve ARGUS_EXPLOIT_LLM routing mode for exploit/payload tasks."""
    val = (os.environ.get("ARGUS_EXPLOIT_LLM") or "auto").strip().lower()
    return val if val in ("auto", "cloud", "wrb") else "auto"


def _any_cloud_key_configured() -> bool:
    """True when at least one cloud provider API key is present in the environment."""
    return any(_get_key(k) for k in _CLOUD_KEY_ENVS)


def _count_tokens_tiktoken(text: str) -> int:
    """Count tokens using tiktoken cl100k_base encoding (lazy-init cached encoder)."""
    global _tiktoken_enc
    if _tiktoken_enc is None:
        import tiktoken
        _tiktoken_enc = tiktoken.get_encoding("cl100k_base")
    return len(_tiktoken_enc.encode(text))


def _record_llm_cost(
    scan_id: str,
    phase: str,
    task_label: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
) -> None:
    """Best-effort cost recording — never raises to the caller."""
    try:
        from src.llm.cost_tracker import get_tracker

        tracker = get_tracker(scan_id)
        try:
            tracker.record(
                phase=phase,
                task=task_label,
                model=model,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
            )
        except Exception:
            pass
    except Exception:
        pass
    try:
        from src.orchestration.cost_aware_reasoning import TokenUsageRecord, get_cost_tracker
        _cost_usd = (prompt_tokens + completion_tokens) * 0.00001
        _record = TokenUsageRecord(
            phase=phase, tier=task_label, model=model,
            prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
            estimated_cost_usd=_cost_usd,
        )
        if scan_id:
            _tracker = get_cost_tracker(scan_id)
            if _tracker is not None:
                _tracker.record(_record)
    except Exception:
        pass


def _get_wrb_adapter():
    """Lazy-load WhiteRabbitNeo adapter — avoids circular imports at module level."""
    from src.llm.whiterabbitneo_adapter import get_whiterabbitneo_adapter
    return get_whiterabbitneo_adapter()


def _cloud_llm_allowed(scan_options: dict | None) -> bool:
    if not scan_options:
        return False
    if scan_options.get("cloud_llm_allowed") is True:
        return True
    quick = scan_options.get("quick")
    return isinstance(quick, dict) and quick.get("cloud_llm_allowed") is True


def _qwythos_base_url() -> str:
    return (os.environ.get("QWYTHOS_URL") or "").strip().rstrip("/")


def _small_model_endpoint() -> tuple[str, str] | None:
    gemma = (os.environ.get("GEMMA_LOCAL_URL") or "").strip().rstrip("/")
    if gemma:
        return gemma, "gemma-2-2b-it"
    qwen = (os.environ.get("QWEN_LOCAL_URL") or "").strip().rstrip("/")
    if qwen:
        return qwen, "qwen3-4b-instruct"
    return None


async def _call_via_local_openai(
    system_prompt: str,
    user_prompt: str,
    *,
    base_url: str,
    model: str,
    task: LLMTask | None = None,
    scan_id: str | None = None,
    phase: str = "unknown",
    timeout_sec: float = _QUICK_DEFAULT_TIMEOUT_SEC,
) -> str:
    """OpenAI-compatible local call (Qwythos / Gemma / Qwen). No cloud keys."""
    if not base_url:
        raise RuntimeError("local_openai_url_missing")
    messages: list[dict[str, str]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": user_prompt})
    payload = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "max_tokens": 4096,
    }
    url = f"{base_url}/chat/completions"
    headers = {"Content-Type": "application/json"}
    timeout = httpx.Timeout(connect=10.0, read=timeout_sec, write=30.0, pool=10.0)
    async with httpx.AsyncClient(timeout=timeout) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()
    choices = data.get("choices", [])
    if not choices:
        raise ValueError("Empty response from local OpenAI-compatible model")
    content = choices[0].get("message", {}).get("content", "")
    text = (content or "").strip()
    if scan_id:
        usage = data.get("usage") or {}
        _record_llm_cost(
            scan_id,
            phase,
            task.value if task else "unknown",
            model,
            int(usage.get("prompt_tokens") or 0),
            int(usage.get("completion_tokens") or 0),
        )
    return text


async def _execute_quick_route(
    system_prompt: str,
    user_prompt: str,
    task: LLMTask,
    *,
    scan_id: str | None,
    phase: str,
    scan_options: dict | None,
) -> str:
    """Quick-mode routing: Qwythos planner/reporter, WRB critic, small fingerprint/triage.

    Cloud is used only for the reporter when ``cloud_llm_allowed`` is true.
    Failures raise so ``llm_routes`` can apply deterministic fallbacks.
    """
    cloud_ok = _cloud_llm_allowed(scan_options)

    if task in _QUICK_QWYTHOS_TASKS:
        qwythos_url = _qwythos_base_url()
        if qwythos_url:
            try:
                return await _call_via_local_openai(
                    system_prompt,
                    user_prompt,
                    base_url=qwythos_url,
                    model="qwythos-9b-claude-mythos-5-1m",
                    task=task,
                    scan_id=scan_id,
                    phase=phase,
                )
            except Exception as exc:
                logger.warning(
                    "quick_qwythos_failed",
                    extra={
                        "event": "quick_qwythos_failed",
                        "task": task.value,
                        "error_type": type(exc).__name__,
                    },
                )
                if task == LLMTask.QUICK_REPORTER and cloud_ok and _any_cloud_key_configured():
                    return await _call_via_task_router(
                        system_prompt, user_prompt, task, scan_id=scan_id, phase=phase
                    )
                raise RuntimeError(f"qwythos_unavailable:{task.value}") from exc
        if task == LLMTask.QUICK_REPORTER and cloud_ok and _any_cloud_key_configured():
            return await _call_via_task_router(
                system_prompt, user_prompt, task, scan_id=scan_id, phase=phase
            )
        raise RuntimeError(f"qwythos_unavailable:{task.value}")

    if task == LLMTask.QUICK_CRITIC:
        wrb = _get_wrb_adapter()
        if wrb.is_configured:
            try:
                async with _get_wrb_semaphore():
                    return await _call_via_whiterabbitneo(
                        system_prompt, user_prompt, task=task, scan_id=scan_id, phase=phase
                    )
            except Exception as exc:
                logger.warning(
                    "quick_wrb_critic_failed",
                    extra={"event": "quick_wrb_critic_failed", "error_type": type(exc).__name__},
                )
                raise RuntimeError("wrb_unavailable:quick_critic") from exc
        raise RuntimeError("wrb_unavailable:quick_critic")

    if task in _QUICK_SMALL_TASKS:
        endpoint = _small_model_endpoint()
        if endpoint is None:
            raise RuntimeError(f"small_model_unavailable:{task.value}")
        base_url, model = endpoint
        try:
            return await _call_via_local_openai(
                system_prompt,
                user_prompt,
                base_url=base_url,
                model=model,
                task=task,
                scan_id=scan_id,
                phase=phase,
            )
        except Exception as exc:
            raise RuntimeError(f"small_model_unavailable:{task.value}") from exc

    raise RuntimeError(f"unsupported_quick_task:{task.value}")


async def _call_via_whiterabbitneo(
    system_prompt: str,
    user_prompt: str,
    *,
    task: LLMTask | None = None,
    scan_id: str | None = None,
    phase: str = "unknown",
) -> str:
    """Call WhiteRabbitNeo adapter, record cost, return text."""
    wrb = _get_wrb_adapter()
    text, usage = await wrb.call_with_usage(
        user_prompt,
        system_prompt=system_prompt,
    )
    if scan_id:
        _record_llm_cost(
            scan_id,
            phase,
            task.value if task else "unknown",
            "taico-ai/WhiteRabbitNeo-v3-7B",
            usage["prompt_tokens"],
            usage["completion_tokens"],
        )
    return text


async def _call_via_task_router(
    system_prompt: str,
    user_prompt: str,
    task: LLMTask,
    *,
    scan_id: str | None = None,
    phase: str = "unknown",
) -> str:
    """Fallback/legacy: call via task_router (cloud providers)."""
    response = await _task_router_call(
        task,
        user_prompt,
        system_prompt=system_prompt,
    )
    if scan_id:
        prompt_tok = response.prompt_tokens
        completion_tok = response.completion_tokens
        if not prompt_tok and not completion_tok:
            prompt_tok = _count_tokens_tiktoken(
                (system_prompt or "") + (user_prompt or "")
            )
            completion_tok = _count_tokens_tiktoken(response.text or "")
        _record_llm_cost(
            scan_id,
            phase,
            task.value,
            response.model,
            prompt_tok,
            completion_tok,
        )
    return response.text


def _annotate_last_cost_record(
    scan_id: str | None, alias: str, fallback_used: bool, latency_ms: int
) -> None:
    """Best-effort: attach routing telemetry to the most recent cost record."""
    if not scan_id:
        return
    try:
        from src.llm.cost_tracker import get_tracker

        tracker = get_tracker(scan_id)
        if tracker.calls:
            rec = tracker.calls[-1]
            rec.alias = alias
            rec.fallback_used = fallback_used
            rec.latency_ms = latency_ms
    except Exception:  # pragma: no cover — telemetry must never break the call path
        pass


async def _execute_phase_route(
    route: PhaseRoute,
    system_prompt: str,
    user_prompt: str,
    task: LLMTask,
    *,
    scan_id: str | None,
    phase: str,
) -> str:
    """Execute a phase-routed LLM call: primary (cloud|wrb) with optional fallback.

    Reuses the existing cloud task_router and WRB adapter (and their key plumbing);
    this only decides ordering per ``phase_routing.yaml``. Telemetry (chosen alias,
    fallback usage, latency) is recorded on the per-scan cost tracker.
    """
    wrb = _get_wrb_adapter()
    started = time.monotonic()
    chosen_alias = route.primary_alias or route.mode
    fallback_used = False

    async def _run_cloud() -> str:
        return await _call_via_task_router(
            system_prompt, user_prompt, task, scan_id=scan_id, phase=phase
        )

    async def _run_wrb() -> str:
        async with _get_wrb_semaphore():
            return await _call_via_whiterabbitneo(
                system_prompt, user_prompt, task=task, scan_id=scan_id, phase=phase
            )

    async def _run_qwythos() -> str:
        url = _qwythos_base_url()
        if not url:
            raise RuntimeError("qwythos_unavailable")
        return await _call_via_local_openai(
            system_prompt,
            user_prompt,
            base_url=url,
            model="qwythos-9b-claude-mythos-5-1m",
            task=task,
            scan_id=scan_id,
            phase=phase,
        )

    async def _run_small() -> str:
        endpoint = _small_model_endpoint()
        if endpoint is None:
            raise RuntimeError("small_model_unavailable")
        base_url, model = endpoint
        return await _call_via_local_openai(
            system_prompt,
            user_prompt,
            base_url=base_url,
            model=model,
            task=task,
            scan_id=scan_id,
            phase=phase,
        )

    def _primary_available() -> bool:
        if route.mode == "cloud":
            return _any_cloud_key_configured()
        if route.mode == "wrb":
            return wrb.is_configured
        if route.mode == "qwythos":
            return bool(_qwythos_base_url())
        if route.mode == "small":
            return _small_model_endpoint() is not None
        return wrb.is_configured

    async def _run_mode(mode: str) -> str:
        if mode == "cloud":
            return await _run_cloud()
        if mode == "qwythos":
            return await _run_qwythos()
        if mode == "small":
            return await _run_small()
        return await _run_wrb()

    try:
        if not _primary_available():
            raise RuntimeError(f"phase route primary '{route.mode}' unavailable")
        text = await _run_mode(route.mode)
    except Exception as exc:
        if route.fallback == "none":
            _annotate_last_cost_record(
                scan_id, chosen_alias, False, int((time.monotonic() - started) * 1000)
            )
            raise
        logger.warning(
            "phase_route_primary_failed",
            extra={
                "event": "phase_route_primary_failed",
                "phase": phase,
                "primary_alias": route.primary_alias,
                "mode": route.mode,
                "fallback": route.fallback,
                "error": str(exc),
            },
        )
        fallback_used = True
        increment_llm_fallback()
        if route.fallback == "cloud":
            if not _any_cloud_key_configured():
                raise
            text = await _run_cloud()
            chosen_alias = f"{route.primary_alias}->cloud_fallback"
        elif route.fallback == "qwythos":
            text = await _run_qwythos()
            chosen_alias = f"{route.primary_alias}->qwythos_fallback"
        elif route.fallback == "small":
            text = await _run_small()
            chosen_alias = f"{route.primary_alias}->small_fallback"
        else:  # wrb
            if not wrb.is_configured:
                raise
            text = await _run_wrb()
            chosen_alias = f"{route.primary_alias}->wrb_fallback"

    latency_ms = int((time.monotonic() - started) * 1000)
    _annotate_last_cost_record(scan_id, chosen_alias, fallback_used, latency_ms)
    logger.info(
        "llm_phase_routing",
        extra={
            "event": "llm_phase_routing",
            "phase": phase,
            "primary_alias": route.primary_alias,
            "mode": route.mode,
            "chosen_alias": chosen_alias,
            "fallback_used": fallback_used,
            "latency_ms": latency_ms,
            "evidence_contract": route.evidence_contract,
        },
    )
    return text


def _safety_monitor_enabled() -> bool:
    return settings.safety_monitor_enabled


def _safety_check_prompt(prompt: str, task: str) -> None:
    if not _safety_monitor_enabled():
        return
    try:
        monitor = get_safety_monitor()
        alert = monitor.check_prompt(prompt, task=task)
        if alert is not None:
            logger.warning(
                "SafetyMonitor alert (prompt)",
                extra={
                    "event": "llm_safety_monitor_prompt_alert",
                    "alert_id": alert.id,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "task": task,
                    "description": alert.description,
                },
            )
    except Exception:
        logger.warning("SafetyMonitor error during prompt check", exc_info=True)


def _safety_check_response(response: str, task: str) -> None:
    if not _safety_monitor_enabled():
        return
    try:
        monitor = get_safety_monitor()
        alert = monitor.check_response(response, task=task)
        if alert is not None:
            logger.warning(
                "SafetyMonitor alert (response)",
                extra={
                    "event": "llm_safety_monitor_response_alert",
                    "alert_id": alert.id,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "task": task,
                    "description": alert.description,
                },
            )
    except Exception:
        logger.warning("SafetyMonitor error during response check", exc_info=True)


async def call_llm_unified(
    system_prompt: str,
    user_prompt: str,
    *,
    task: LLMTask | None = None,
    model: str | None = None,
    scan_id: str | None = None,
    phase: str = "unknown",
    response_schema_id: str | None = None,
    use_unified: bool = False,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    execution_mode: ExecutionMode | str | None = None,
    preferred_alias: str | None = None,
    content_class: ContentClass | str | None = None,
    scan_options: dict | None = None,
    prompt_id: str | None = None,
) -> str:
    """Primary async entry point for every LLM call in ARGUS.

    Routing (WRB-001):
      - Pentest tasks → WhiteRabbitNeo ONLY (local, $0). Fails closed with a
        RuntimeError when WRB is unavailable or not configured — cloud fallback
        is never permitted for analysis tasks.
      - Report tasks → WhiteRabbitNeo first, cloud fallback if unavailable
      - OSINT tasks → Perplexity directly (WRB has no internet access)
      - No task → legacy generic router

    When ``settings.argus_unified_llm_gateway`` is True and *task* is set,
    requests go through ``UnifiedLlmGateway`` (alias → real provider/model,
    mode-aware prompts, sequential fallback). Flag False keeps the legacy path.

    ``execution_mode`` is optional. When omitted, the facade tries scan options
    then the request-scoped contextvar, then defaults to production and emits a
    structured warning (not a hard fail) if the unified gateway is on.

    When *scan_id* is provided, token usage is recorded to the per-scan cost
    tracker (best-effort, never fails the main flow).

    Returns the model's text response.
    """
    _safety_check_prompt(user_prompt, task.value if task else "none")

    # Phase-aware routing (opt-in via ARGUS_PHASE_ROUTING_ENABLED) takes
    # precedence over the generic unified gateway: when an operator explicitly
    # enables it and the phase is mapped, the phase route below governs
    # primary/fallback ordering. Default OFF → ``get_phase_route`` returns None
    # and the unified-gateway path is unchanged (no behaviour change by default).
    _phase_route_active = get_phase_route(phase) is not None
    if not _phase_route_active and _should_use_unified_gateway(
        task, response_schema_id, use_unified
    ):
        result = await _call_via_unified_gateway(
            system_prompt,
            user_prompt,
            task,
            scan_id=scan_id,
            phase=phase,
            response_schema_id=response_schema_id,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            execution_mode=execution_mode,
            preferred_alias=preferred_alias,
            content_class=content_class,
            scan_options=scan_options,
            prompt_id=prompt_id,
        )
        _safety_check_response(result, task.value)
        return result

    wrb = _get_wrb_adapter()

    if task is None:
        warnings.warn(
            "call_llm_unified() called without task= parameter. "
            "Pass an LLMTask value for optimal routing and cost tracking. "
            "Falling back to generic router.",
            DeprecationWarning,
            stacklevel=2,
        )
        # Legacy: no WRB, generic router
        result = await _router_call_llm(
            user_prompt,
            system_prompt=system_prompt,
            model=model,
        )
        if scan_id:
            input_tokens = _count_tokens_tiktoken(
                (system_prompt or "") + (user_prompt or "")
            )
            output_tokens = _count_tokens_tiktoken(result or "")
            _record_llm_cost(
                scan_id,
                phase,
                "generic_router",
                model or "unknown",
                input_tokens,
                output_tokens,
            )
        _safety_check_response(result, task.value if task else "none")
        return result

    # OSINT tasks — Perplexity directly (internet access required)
    if task == LLMTask.PERPLEXITY_OSINT:
        result = await _call_via_task_router(
            system_prompt, user_prompt, task,
            scan_id=scan_id, phase=phase,
        )
        _safety_check_response(result, task.value)
        return result

    # Quick execution mode: Qwythos planner/reporter, WRB critic, small fingerprint/triage.
    # Explicit exception to WRB-only analysis routing (WRB-001). Must run before
    # phase routing so cloud_llm_allowed and local fallbacks stay on this path.
    # Production vuln_analysis is unchanged.
    if task in _QUICK_TASKS:
        result = await _execute_quick_route(
            system_prompt,
            user_prompt,
            task,
            scan_id=scan_id,
            phase=phase,
            scan_options=scan_options,
        )
        _safety_check_response(result, task.value)
        return result

    # Phase-aware routing (opt-in via ARGUS_PHASE_ROUTING_ENABLED). When a route
    # exists for this phase, it fully governs primary/fallback ordering and
    # supersedes the legacy WRB-first / cloud-preferred blocks below.
    _route = get_phase_route(phase)
    if _route is not None:
        result = await _execute_phase_route(
            _route, system_prompt, user_prompt, task,
            scan_id=scan_id, phase=phase,
        )
        _safety_check_response(result, task.value)
        return result

    # Exploit / PoC payload generation — prefer a cloud model for valid-JSON output.
    if task in _CLOUD_PREFERRED_TASKS:
        mode = _exploit_llm_mode()
        if mode != "wrb" and _any_cloud_key_configured():
            try:
                result = await _call_via_task_router(
                    system_prompt, user_prompt, task,
                    scan_id=scan_id, phase=phase,
                )
                _safety_check_response(result, task.value)
                return result
            except Exception as exc:
                logger.warning(
                    "exploit_cloud_llm_failed",
                    extra={
                        "event": "exploit_cloud_llm_failed",
                        "task": task.value,
                        "phase": phase,
                        "error": str(exc),
                    },
                )
                if mode == "cloud":
                    raise
                # mode == "auto": fall through to WhiteRabbitNeo below.
        elif mode == "cloud":
            raise RuntimeError(
                f"ARGUS_EXPLOIT_LLM=cloud requires a cloud provider API key for task "
                f"{task.value}, but none is configured. Set one of "
                f"{', '.join(_CLOUD_KEY_ENVS)} or use ARGUS_EXPLOIT_LLM=auto."
            )

    # WhiteRabbitNeo configured: use it first for ALL non-OSINT tasks
    if wrb.is_configured:
        semaphore = _get_wrb_semaphore()
        async with semaphore:
            try:
                result = await _call_via_whiterabbitneo(
                    system_prompt, user_prompt,
                    task=task, scan_id=scan_id, phase=phase,
                )
                _safety_check_response(result, task.value)
                return result
            except Exception as exc:
                logger.warning(
                    "whiterabbitneo_call_failed",
                    extra={
                        "event": "whiterabbitneo_call_failed",
                        "task": task.value,
                        "phase": phase,
                        "error": str(exc),
                    },
                )
                # Cloud fallback only for report-supplement tasks
                if task in _CLOUD_FALLBACK_TASKS:
                    logger.info(
                        "whiterabbitneo_fallback_to_cloud",
                        extra={
                            "event": "whiterabbitneo_fallback_to_cloud",
                            "task": task.value,
                        },
                    )
                    result = await _call_via_task_router(
                        system_prompt, user_prompt, task,
                        scan_id=scan_id, phase=phase,
                    )
                    _safety_check_response(result, task.value)
                    return result
                net_hint = ""
                if isinstance(exc, httpx.TimeoutException):
                    net_hint = (
                        "Таймаут HTTP к WRB (часто llama.cpp на CPU с длинным промптом). "
                        "Увеличьте WHITERABBITNEO_TIMEOUT_SEC в infra/.env (например 900–1800). "
                    )
                elif isinstance(exc, httpx.ConnectError):
                    net_hint = "Нет TCP-соединения с WRB (контейнер не запущен или неверный WHITERABBITNEO_URL). "
                raise RuntimeError(
                    f"WhiteRabbitNeo unavailable for pentest task {task.value}. "
                    f"{net_hint}"
                    "Cloud fallback is not permitted for analysis tasks. "
                    "Ensure WRB container is running and responsive."
                ) from exc

    # WRB not configured. Report-supplement tasks may still use cloud providers
    # (formatting only — no sensitive pentest data). Analysis tasks MUST fail
    # closed: silently shipping target details, discovered findings, or
    # exploitation reasoning to a cloud provider would violate the local-only
    # confidentiality invariant (WRB-001) that pentest analysis never leaves the
    # box. Exploit/PoC tasks reach this point only when no cloud path applied
    # earlier (no key, or ARGUS_EXPLOIT_LLM=wrb), so they fail closed too.
    if task in _CLOUD_FALLBACK_TASKS:
        logger.info(
            "whiterabbitneo_not_configured_using_cloud_fallback",
            extra={
                "event": "whiterabbitneo_not_configured",
                "task": task.value,
            },
        )
        result = await _call_via_task_router(
            system_prompt, user_prompt, task,
            scan_id=scan_id, phase=phase,
        )
        _safety_check_response(result, task.value)
        return result

    logger.error(
        "whiterabbitneo_not_configured_fail_closed",
        extra={
            "event": "whiterabbitneo_not_configured_fail_closed",
            "task": task.value,
            "phase": phase,
        },
    )
    raise RuntimeError(
        f"WhiteRabbitNeo is not configured, but pentest analysis task "
        f"{task.value} requires it. Cloud fallback is not permitted for "
        f"analysis tasks — pentest analysis must stay local (WRB-001). "
        f"Set WHITERABBITNEO_URL so the local model is reachable."
    )


def call_llm_sync(
    system_prompt: str,
    user_prompt: str,
    *,
    task: LLMTask | None = None,
    model: str | None = None,
    scan_id: str | None = None,
    phase: str = "unknown",
    response_schema_id: str | None = None,
    use_unified: bool = False,
    tenant_id: str | None = None,
    engagement_id: str | None = None,
    execution_mode: ExecutionMode | str | None = None,
    preferred_alias: str | None = None,
    content_class: ContentClass | str | None = None,
    scan_options: dict | None = None,
    prompt_id: str | None = None,
) -> str:
    """Sync wrapper for contexts that cannot use ``await``.

    Safe to call from Celery workers, Jinja rendering helpers, or any other
    synchronous code path.  When already inside a running event loop the
    coroutine is executed in a dedicated thread to avoid "cannot run nested
    event loop" errors.

    Every path is bounded by ``_SYNC_TIMEOUT_SECONDS`` (``asyncio.wait_for``)
    so a hung WRB cannot block a Celery worker indefinitely.
    """

    def _make_coro():
        return call_llm_unified(
            system_prompt,
            user_prompt,
            task=task,
            model=model,
            scan_id=scan_id,
            phase=phase,
            response_schema_id=response_schema_id,
            use_unified=use_unified,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            execution_mode=execution_mode,
            preferred_alias=preferred_alias,
            content_class=content_class,
            scan_options=scan_options,
            prompt_id=prompt_id,
        )

    def _run_bounded() -> str:
        return asyncio.run(asyncio.wait_for(_make_coro(), timeout=_SYNC_TIMEOUT_SECONDS))

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_run_bounded)
            return future.result(timeout=_SYNC_TIMEOUT_SECONDS + 30.0)

    return _run_bounded()


async def call_llm_with_escalation(
    system_prompt: str,
    user_prompt: str,
    *,
    task: LLMTask,
    confidence_extractor: "callable | None" = None,
    max_escalations: int = 1,
    scan_id: str | None = None,
    phase: str = "unknown",
    execution_mode: ExecutionMode | str | None = None,
    scan_options: dict | None = None,
) -> str:
    """Call LLM with automatic tier escalation on low confidence.

    If the initial response confidence is below the task's escalation threshold,
    automatically re-runs with the next tier model (small -> medium -> large).

    Parameters
    ----------
    confidence_extractor : callable or None
        Function that takes the LLM response text and returns a float 0.0-1.0.
        If None, a simple heuristic based on hedging language is used.
    max_escalations : int
        Maximum number of escalation attempts (1 = at most one re-run).
    """
    response_text = await call_llm_unified(
        system_prompt, user_prompt,
        task=task, scan_id=scan_id, phase=phase,
        execution_mode=execution_mode,
        scan_options=scan_options,
    )

    if not response_text or max_escalations <= 0:
        return response_text

    confidence = 0.7
    if confidence_extractor is not None:
        try:
            confidence = float(confidence_extractor(response_text))
        except (TypeError, ValueError):
            confidence = 0.7
    else:
        hedge_words = ["might", "could be", "possibly", "perhaps", "maybe", "it seems", "uncertain"]
        lower = response_text.lower()
        hedges_found = sum(1 for w in hedge_words if w in lower)
        confidence = max(0.3, 1.0 - (hedges_found * 0.1))

    escalation = check_tier_escalation(task, confidence)

    if not escalation.escalated:
        return response_text

    logger.info(
        "confidence_escalation",
        extra={
            "event": "confidence_escalation",
            "task": task.value,
            "original_tier": escalation.original_tier.value if hasattr(escalation.original_tier, 'value') else str(escalation.original_tier),
            "escalated_tier": escalation.escalated_tier.value if hasattr(escalation.escalated_tier, 'value') else str(escalation.escalated_tier),
            "confidence": confidence,
            "threshold": escalation.threshold,
            "scan_id": scan_id,
            "phase": phase,
        },
    )

    escalated_response = await call_llm_unified(
        system_prompt,
        f"[ESCALATED RE-RUN — confidence was {confidence:.2f}, threshold {escalation.threshold:.2f}]\n\n{user_prompt}",
        task=task,
        scan_id=scan_id,
        phase=f"{phase}_escalated",
        execution_mode=execution_mode,
        scan_options=scan_options,
    )

    return escalated_response if escalated_response else response_text
