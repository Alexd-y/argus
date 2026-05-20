"""Unified LLM entry point — single source of truth for all LLM calls in ARGUS.

WhiteRabbitNeo V3 7B is the primary AI for ALL pentest analysis tasks.
Cloud providers (DeepSeek, OpenAI, Perplexity) serve only as supplements
for report formatting and OSINT enrichment.

Routing logic:
  - Pentest tasks (ORCHESTRATION, THREAT_MODELING, …) → WhiteRabbitNeo ONLY
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
import warnings

import httpx

from src.llm.router import call_llm as _router_call_llm
from src.llm.task_router import LLMTask
from src.llm.task_router import call_llm_for_task as _task_router_call

logger = logging.getLogger(__name__)

_SYNC_TIMEOUT_SECONDS = 300

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
        tracker.record(
            phase=phase,
            task=task_label,
            model=model,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
        )
    except Exception:
        logger.warning("cost_tracking_record_failed", exc_info=True)


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
      - Pentest tasks → WhiteRabbitNeo ONLY (local, $0, no cloud fallback)
      - Report tasks → WhiteRabbitNeo first, cloud fallback if unavailable
      - OSINT tasks → Perplexity directly (WRB has no internet access)
      - No task → legacy generic router

    When *scan_id* is provided, token usage is recorded to the per-scan cost
    tracker (best-effort, never fails the main flow).

    Returns the model's text response.
    """
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
        return result

    # OSINT tasks — Perplexity directly (internet access required)
    if task == LLMTask.PERPLEXITY_OSINT:
        return await _call_via_task_router(
            system_prompt, user_prompt, task,
            scan_id=scan_id, phase=phase,
        )

    # WhiteRabbitNeo configured: use it first for ALL non-OSINT tasks
    if wrb.is_configured:
        semaphore = _get_wrb_semaphore()
        async with semaphore:
            try:
                return await _call_via_whiterabbitneo(
                    system_prompt, user_prompt,
                    task=task, scan_id=scan_id, phase=phase,
                )
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
                    return await _call_via_task_router(
                        system_prompt, user_prompt, task,
                        scan_id=scan_id, phase=phase,
                    )
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

    # WRB not configured: legacy behaviour — use cloud task_router
    logger.info(
        "whiterabbitneo_not_configured_using_cloud_fallback",
        extra={
            "event": "whiterabbitneo_not_configured",
            "task": task.value,
        },
    )
    return await _call_via_task_router(
        system_prompt, user_prompt, task,
        scan_id=scan_id, phase=phase,
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
