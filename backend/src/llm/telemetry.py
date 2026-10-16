"""Unified LLM invocation telemetry (Wave 5, R-9.1).

Both LLM paths in ARGUS must land in ONE telemetry table so the dataset is
complete:

* the cloud gateway (``src/llm_gateway/router.py`` → ``usage_ledger.record_usage``);
* the PRIMARY WhiteRabbitNeo / local path (``src/llm/facade.py``), which until
  Wave 5 recorded only to the *budget* ledger and never reached
  ``gateway_invocations``.

This module is the seam that routes the facade path into the SAME single
writer — ``src.llm_gateway.usage_ledger.record_usage`` — rather than spawning a
second telemetry store. The budget ledger is left untouched: it is about money,
this is about data (R-9.1), and the two roles are not merged.

Tenant / scan / phase context
-----------------------------
The facade leaf callers run inside Celery workers, outside any FastAPI request
scope, so ``get_current_tenant_id`` is unavailable to them. The orchestrator
therefore stamps a per-phase scope (tenant_id + scan_id + phase) via
:func:`llm_telemetry_scope` around the phase-handler dispatch; the recorder
reads it from a :class:`contextvars.ContextVar`. Explicit ``scan_id`` / ``phase``
arguments still win when a caller knows better.

The recorder is best-effort and NEVER raises into the LLM call path.
"""

from __future__ import annotations

import hashlib
import logging
from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any

logger = logging.getLogger(__name__)

# (tenant_id, scan_id, phase) stamped by the orchestrator per phase.
_scope_var: ContextVar[dict[str, str] | None] = ContextVar("llm_telemetry_scope", default=None)


@contextmanager
def llm_telemetry_scope(
    *,
    tenant_id: str = "",
    scan_id: str = "",
    phase: str = "",
) -> Iterator[None]:
    """Stamp the telemetry scope for every LLM call made inside this block.

    Nestable; the previous scope is restored on exit. Used by the scan state
    machine around phase-handler dispatch so facade calls inherit tenant/scan.
    """
    token = _scope_var.set(
        {
            "tenant_id": tenant_id or "",
            "scan_id": scan_id or "",
            "phase": phase or "",
        }
    )
    try:
        yield
    finally:
        _scope_var.reset(token)


def current_telemetry_scope() -> dict[str, str]:
    """Return the active scope (empty strings when none is set)."""
    scope = _scope_var.get()
    if scope is None:
        return {"tenant_id": "", "scan_id": "", "phase": ""}
    return dict(scope)


def _sha256_hex(text: str | None) -> str:
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def record_llm_invocation(
    *,
    task: Any = "",
    provider: str = "",
    model: str = "",
    prompt_text: str | None = None,
    response_text: str | None = None,
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    status: str = "completed",
    error_code: str = "",
    latency_ms: int = 0,
    alias: str = "",
    scan_id: str | None = None,
    phase: str | None = None,
    tenant_id: str | None = None,
) -> None:
    """Record one LLM invocation into the single unified telemetry writer.

    Best-effort: any failure is swallowed (debug-logged) so telemetry can never
    break the LLM call path. ``task`` accepts an ``LLMTask`` enum or a string.
    """
    try:
        scope = current_telemetry_scope()
        resolved_tenant = tenant_id if tenant_id is not None else scope["tenant_id"]
        resolved_scan = scan_id if scan_id is not None else scope["scan_id"]
        resolved_phase = phase if phase is not None else scope["phase"]
        task_label = getattr(task, "value", task) or ""

        from src.llm.telemetry_text_store import store_redacted_text

        prompt_object_key = store_redacted_text(
            tenant_id=resolved_tenant or "",
            scan_id=resolved_scan or "",
            kind="prompt",
            text=prompt_text,
        )
        response_object_key = store_redacted_text(
            tenant_id=resolved_tenant or "",
            scan_id=resolved_scan or "",
            kind="response",
            text=response_text,
        )

        from src.llm_gateway.usage_ledger import record_usage

        record_usage(
            tenant_id=resolved_tenant or "",
            scan_id=resolved_scan or "",
            phase=resolved_phase or "",
            task=str(task_label),
            alias=alias,
            provider=provider,
            model=model,
            prompt_tokens=int(prompt_tokens or 0),
            completion_tokens=int(completion_tokens or 0),
            estimated_cost=0.0,
            status=status,
            error_code=error_code,
            latency_ms=int(latency_ms or 0),
            prompt_hash=_sha256_hex(prompt_text),
            response_hash=_sha256_hex(response_text),
            prompt_object_key=prompt_object_key,
            response_object_key=response_object_key,
        )
    except Exception:  # pragma: no cover - defensive; telemetry never breaks calls
        logger.debug("record_llm_invocation: suppressed best-effort error", exc_info=True)


__all__ = [
    "current_telemetry_scope",
    "llm_telemetry_scope",
    "record_llm_invocation",
]
