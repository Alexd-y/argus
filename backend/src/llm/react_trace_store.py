"""Persist the full ReAct reasoning trace (Wave 5, R-9.4).

The ReAct agent produced its trace only in memory; only summary scalars were
ever logged. This module persists the WHOLE trace — scalar metadata inline, the
ordered steps (Thought/Action/Observation incl. tool results) redacted into
object storage — because the intermediate steps are the most valuable part for
analysis and possible training.

Off unless ``settings.react_trace_persist`` is set (it adds a DB write per ReAct
run). Tenant/scan/phase/task are resolved from the telemetry scope stamped by
the scan state machine (same ContextVar as the unified telemetry seam). The step
CONTENT is stored only when text capture is also authorized for the tenant
(reuses :func:`src.llm.telemetry_text_store.store_redacted_text`). Best-effort:
never raises into the ReAct call path; writes in a fresh, isolated session.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)


def _steps_to_json(result: Any) -> str:
    steps = getattr(result, "steps", None) or []
    payload = []
    for s in steps:
        step_type = getattr(s, "step_type", "")
        payload.append(
            {
                "step_type": getattr(step_type, "value", step_type),
                "content": getattr(s, "content", ""),
                "tool_name": getattr(s, "tool_name", None),
                "tool_args": getattr(s, "tool_args", None),
                "tool_result": getattr(s, "tool_result", None),
                "timestamp": getattr(s, "timestamp", None),
            }
        )
    return json.dumps(payload, default=str)


async def persist_react_trace(
    *,
    result: Any,
    scan_id: str | None = None,
    phase: str | None = None,
    task: str = "",
) -> str | None:
    """Persist one ReAct trace. Returns the new row id, or ``None`` (noop/error).

    Gated by ``settings.react_trace_persist`` and the presence of a tenant in the
    telemetry scope. Best-effort — never raises.
    """
    try:
        from src.core.config import settings

        if not getattr(settings, "react_trace_persist", False):
            return None

        from src.llm.telemetry import current_telemetry_scope

        scope = current_telemetry_scope()
        tenant_id = scope["tenant_id"]
        resolved_scan = scan_id if scan_id is not None else scope["scan_id"]
        resolved_phase = phase if phase is not None else scope["phase"]
        if not tenant_id:
            return None

        from src.llm.telemetry_text_store import store_redacted_text

        steps_object_key = store_redacted_text(
            tenant_id=tenant_id,
            scan_id=resolved_scan or "",
            kind="react_trace",
            text=_steps_to_json(result),
        )

        answer = getattr(result, "answer", "") or ""
        steps = getattr(result, "steps", None) or []

        from src.db.models import ReactTrace
        from src.db.session import async_session_factory, set_session_tenant

        row_id = str(uuid.uuid4())
        async with async_session_factory() as session:
            await set_session_tenant(session, tenant_id)
            row = ReactTrace(
                id=row_id,
                tenant_id=tenant_id,
                scan_id=resolved_scan or None,
                phase=resolved_phase or None,
                task=task or None,
                answer_hash=hashlib.sha256(answer.encode("utf-8")).hexdigest() if answer else None,
                iterations=int(getattr(result, "iterations", 0) or 0),
                steps_count=len(steps),
                confidence=float(getattr(result, "confidence", 0.0) or 0.0),
                total_duration_seconds=float(getattr(result, "total_duration_seconds", 0.0) or 0.0),
                stop_reason=str(getattr(result, "stop_reason", "") or "")[:32] or None,
                evidence_backed=bool(getattr(result, "evidence_backed", False)),
                error=str(getattr(result, "error", "") or "")[:256] or None,
                steps_object_key=steps_object_key or None,
            )
            session.add(row)
            await session.commit()
        return row_id
    except Exception:  # pragma: no cover - defensive; telemetry never breaks calls
        logger.debug("persist_react_trace: suppressed best-effort error", exc_info=True)
        return None


__all__ = ["persist_react_trace"]
