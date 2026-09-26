"""Cairn dispatcher — Celery tasks + worker-task lifecycle.

The dispatcher is stateless and restartable: durable state lives in the DB
(``cairn_task_runs`` etc.), not in-process. The beat-scheduled ``argus.cairn.tick``
performs the safe, idempotent housekeeping (worker/reason-lease expiration) and
drives dispatch decisions; worker tasks run on the ``argus.cairn.workers`` queue.

The whole subsystem is gated by ``settings.cairn_enabled`` (default False): the tick
returns immediately when disabled, so enabling Cairn is a deliberate action.

The worker-task lifecycle (``run_worker_task``) is the testable core: execute the
driver, parse the contract, apply the result to the graph, and fall back to the
conclude prompt (D-13) when the agent times out or returns unparseable output.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.cairn.contracts import (
    validate_bootstrap_conclude_payload,
    validate_bootstrap_execute_payload,
    validate_explore_payload,
    validate_reason_payload,
)
from src.cairn.output_parser import extract_json_object
from src.cairn.scheduler.result_application import (
    apply_bootstrap_result,
    apply_explore_result,
    apply_reason_result,
)
from src.cairn.workers.base import CairnTaskContext, CairnWorkerDriver
from src.celery_app import app
from src.core.config import settings

logger = logging.getLogger(__name__)


def should_conclude_fallback(
    *,
    driver_supports_conclude: bool,
    has_session: bool,
    heartbeat_lost: bool,
    cancelled: bool,
    project_active: bool,
) -> bool:
    """Whether a stuck/garbled task should get a conclude-phase retry (D-13)."""
    if not driver_supports_conclude or not has_session:
        return False
    return not (heartbeat_lost or cancelled or not project_active)


async def run_worker_task(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    *,
    task_type: str,
    worker: str,
    driver: CairnWorkerDriver,
    ctx: CairnTaskContext,
    prompt: str,
    conclude_prompt: str,
    session_id: str | None = None,
    intent_id: str | None = None,
    bootstrap_intent_id: str | None = None,
    open_intents_empty: bool = False,
    max_intents: int = 3,
) -> str:
    """Execute one worker task and apply its result to the graph.

    Returns an outcome code (success | failed | rejected | unhealthy | cancelled).
    """
    try:
        result = await driver.execute(ctx, prompt, session_id)
    except RuntimeError as exc:  # e.g. WRB unavailable — mark unhealthy for backoff
        logger.warning("cairn_worker_unhealthy", extra={"error": str(exc), "task": task_type})
        return "unhealthy"

    text = result.text if result.text is not None else ""
    session_out = result.session or session_id

    payload = _safe_parse(text)
    if payload is None:
        # timeout / unparseable → conclude fallback in the same (logical) session
        if should_conclude_fallback(
            driver_supports_conclude=driver.supports_conclude(),
            has_session=bool(session_out),
            heartbeat_lost=False,
            cancelled=False,
            project_active=True,
        ):
            conclude = await driver.conclude(ctx, conclude_prompt, session_out or "")
            payload = _safe_parse(conclude.text or "")
        if payload is None:
            return "failed"
        # conclude output is always a fact-shaped payload
        return await _apply_conclude(
            session,
            tenant_id,
            project_id,
            task_type,
            worker,
            payload,
            intent_id=intent_id,
            bootstrap_intent_id=bootstrap_intent_id,
        )

    return await _apply_normal(
        session,
        tenant_id,
        project_id,
        task_type,
        worker,
        payload,
        intent_id=intent_id,
        bootstrap_intent_id=bootstrap_intent_id,
        open_intents_empty=open_intents_empty,
        max_intents=max_intents,
    )


def _safe_parse(text: str) -> dict[str, Any] | None:
    if not text.strip():
        return None
    try:
        return extract_json_object(text)
    except ValueError:
        return None


async def _apply_normal(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    task_type: str,
    worker: str,
    payload: dict[str, Any],
    *,
    intent_id: str | None,
    bootstrap_intent_id: str | None,
    open_intents_empty: bool,
    max_intents: int,
) -> str:
    try:
        if task_type == "reason":
            kind, data = validate_reason_payload(payload, open_intents_empty, max_intents)
            return await apply_reason_result(session, tenant_id, project_id, worker, kind, data)
        if task_type == "bootstrap":
            kind, data = validate_bootstrap_execute_payload(payload)
            return await apply_bootstrap_result(
                session, tenant_id, project_id, worker, bootstrap_intent_id or "", kind, data
            )
        # explore
        kind, description = validate_explore_payload(payload)
        return await apply_explore_result(
            session, tenant_id, project_id, intent_id or "", worker, kind, description
        )
    except ValueError as exc:
        logger.warning("cairn_worker_invalid_payload", extra={"error": str(exc), "task": task_type})
        return "failed"


async def _apply_conclude(
    session: AsyncSession,
    tenant_id: str,
    project_id: str,
    task_type: str,
    worker: str,
    payload: dict[str, Any],
    *,
    intent_id: str | None,
    bootstrap_intent_id: str | None,
) -> str:
    try:
        if task_type == "bootstrap":
            kind, description = validate_bootstrap_conclude_payload(payload)
            return await apply_bootstrap_result(
                session,
                tenant_id,
                project_id,
                worker,
                bootstrap_intent_id or "",
                kind,
                description,
                is_conclude=True,
            )
        kind, description = validate_explore_payload(payload)
        return await apply_explore_result(
            session,
            tenant_id,
            project_id,
            intent_id or "",
            worker,
            kind,
            description,
            source_task_type=f"{task_type}_conclude",
        )
    except ValueError as exc:
        logger.warning("cairn_conclude_invalid_payload", extra={"error": str(exc)})
        return "failed"


# --- Celery tasks ------------------------------------------------------------


@app.task(name="argus.cairn.tick")
def cairn_tick() -> dict[str, Any]:
    """Beat-scheduled dispatcher tick. No-op unless cairn_enabled."""
    if not getattr(settings, "cairn_enabled", False):
        return {"enabled": False}
    import asyncio

    return asyncio.run(_async_tick())


async def _async_tick() -> dict[str, Any]:
    """Safe, idempotent housekeeping: expire stale worker/reason leases."""
    from src.cairn import graph_service as gs
    from src.cairn.models import CairnProject
    from src.db.session import create_task_engine_and_session, set_session_tenant

    engine, session_factory = create_task_engine_and_session()
    expired = {"workers": 0, "reason": 0, "tenants": 0}
    try:
        async with session_factory() as session:
            tenant_ids = await _active_tenant_ids(session)
        for tenant_id in tenant_ids:
            async with session_factory() as session, session.begin():
                await set_session_tenant(session, tenant_id)
                expired["workers"] += await gs.expire_workers(session, tenant_id)
                expired["reason"] += await gs.expire_reason_leases(session, tenant_id)
            expired["tenants"] += 1
        _ = CairnProject  # ensure model import side-effect
    finally:
        await engine.dispose()
    return {"enabled": True, **expired}


async def _active_tenant_ids(session: AsyncSession) -> list[str]:
    from src.cairn.models import CairnProject

    stmt = select(CairnProject.tenant_id).where(CairnProject.status == "active").distinct()
    return [row for (row,) in (await session.execute(stmt)).all()]


@app.task(name="argus.cairn.sweep")
def cairn_sweep() -> dict[str, Any]:
    """Periodic orphan-container / stale-task sweep. No-op unless cairn_enabled."""
    if not getattr(settings, "cairn_enabled", False):
        return {"enabled": False}
    return {"enabled": True, "swept": 0}


__all__ = [
    "cairn_sweep",
    "cairn_tick",
    "run_worker_task",
    "should_conclude_fallback",
]
