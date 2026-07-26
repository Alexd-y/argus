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
import logging
import os
import time
import warnings

import httpx

from src.governance.safety.monitor import get_safety_monitor

from src.llm.adapters import _get_key
from src.llm.phase_routing import PhaseRoute, get_phase_route
from src.llm.router import call_llm as _router_call_llm
from src.llm.task_router import LLMTask
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

    def _primary_available() -> bool:
        return _any_cloud_key_configured() if route.mode == "cloud" else wrb.is_configured

    try:
        if not _primary_available():
            raise RuntimeError(f"phase route primary '{route.mode}' unavailable")
        text = await (_run_cloud() if route.mode == "cloud" else _run_wrb())
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
        if route.fallback == "cloud":
            if not _any_cloud_key_configured():
                raise
            text = await _run_cloud()
            chosen_alias = f"{route.primary_alias}->cloud_fallback"
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
    val = (os.environ.get("SAFETY_MONITOR_ENABLED") or "true").strip().lower()
    return val in {"true", "1", "yes", "on"}


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
) -> str:
    """Primary async entry point for every LLM call in ARGUS.

    Routing (WRB-001):
      - Pentest tasks → WhiteRabbitNeo ONLY (local, $0). Fails closed with a
        RuntimeError when WRB is unavailable or not configured — cloud fallback
        is never permitted for analysis tasks.
      - Report tasks → WhiteRabbitNeo first, cloud fallback if unavailable
      - OSINT tasks → Perplexity directly (WRB has no internet access)
      - No task → legacy generic router

    When *scan_id* is provided, token usage is recorded to the per-scan cost
    tracker (best-effort, never fails the main flow).

    Returns the model's text response.
    """
    _safety_check_prompt(user_prompt, task.value if task else "none")

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
    )

    return escalated_response if escalated_response else response_text
