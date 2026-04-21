"""Unified LLM entry point — single source of truth for all LLM calls in ARGUS.

All callers should use these functions.  Internal routing goes through
task_router when a task type is specified, otherwise through the generic
sequential-fallback router.

BKL-006: eliminates the three-way split between router / task_router / llm_config.
FIX-004: integrates ScanCostTracker — every LLM call records token usage when scan_id is provided.
LLM-004/M-3: token counting via response.usage primary, tiktoken cl100k_base fallback.
AUD4-003/M-1: deprecation warning when task=None; tiktoken only as fallback.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import warnings

from src.llm.router import call_llm as _router_call_llm
from src.llm.task_router import LLMTask
from src.llm.task_router import call_llm_for_task as _task_router_call

logger = logging.getLogger(__name__)

_SYNC_TIMEOUT_SECONDS = 120

_tiktoken_enc = None


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

    When *task* is provided the call is routed via the task-based routing table
    (optimal provider/model per task type with fallback chain).  Otherwise the
    generic sequential-fallback router is used.

    When *scan_id* is provided, token usage is recorded to the per-scan cost
    tracker (best-effort, never fails the main flow).

    Returns the model's text response.
    """
    if task is None:
        warnings.warn(
            "call_llm_unified() called without task= parameter. "
            "Pass an LLMTask value for optimal routing and cost tracking. "
            "Falling back to generic router.",
            DeprecationWarning,
            stacklevel=2,
        )

    if task is not None:
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
    """
    coro = call_llm_unified(
        system_prompt,
        user_prompt,
        task=task,
        model=model,
        scan_id=scan_id,
        phase=phase,
    )

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop is not None and loop.is_running():
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(asyncio.run, coro)
            return future.result(timeout=_SYNC_TIMEOUT_SECONDS)

    return asyncio.run(coro)
