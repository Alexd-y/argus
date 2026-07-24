"""Celery task that executes an Intruder attack on the high-volume pool (WB-P4b).

The API layer only *dispatches* — the actual send loop runs here, on the
dedicated ``argus.intruder.highvol`` queue, so a high-volume attack can never
starve the scan / report / tool queues. The task is a thin orchestration shell
around the offline-verified :class:`~src.web_workbench.intruder.service.
IntruderService`:

1. Load the attack + its project (tenant-scoped, RLS applied).
2. **Kill-switch** — refuse to run unless the project is ``active``.
3. Materialise payload sets from the signed ``PayloadRegistry`` (SI-5) — the
   attack row stores only references (family id / pipeline / parameters).
4. Run the attack through the mandatory :class:`ForwardGate` (scope) inside
   ``IntruderService``; the control hook polls the persisted status so an
   operator ``pause``/``cancel`` (a status write via the API) halts the run
   promptly.

Live network egress means this task is exercised only on the running stack;
the pure helpers (:func:`control_from_status`, :func:`materialize_payload_sets`)
are unit-tested offline.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, TypeVar

from src.celery_app import app
from src.db.session import create_task_engine_and_session, set_session_tenant
from src.payloads.builder import PayloadBuilder, PayloadBuildRequest
from src.payloads.registry import PayloadRegistry
from src.web_workbench.contracts import ProjectStatus
from src.web_workbench.intruder.repository import (
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_PAUSED,
    IntruderRepository,
)
from src.web_workbench.intruder.service import AttackControl, IntruderService
from src.web_workbench.projects.repository import WorkbenchProjectRepository
from src.web_workbench.projects.service import ProjectScopeService
from src.web_workbench.repeater.sender import HttpxSender

logger = logging.getLogger(__name__)

_T = TypeVar("_T")

#: Celery task name (routed to ``argus.intruder.highvol`` in ``celery_app``).
TASK_NAME = "argus.wb.intruder.run"


def _run_coro_in_thread(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run ``coro`` to completion on a fresh event loop in a worker thread.

    The Intruder control hook is a *sync* callable invoked from inside the
    already-running ``run_attack`` loop, so ``asyncio.run`` there would raise
    "cannot be called from a running event loop". Running the short status
    read on its own thread/loop keeps the poll non-blocking-safe.
    """
    with ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def control_from_status(status: str | None) -> AttackControl:
    """Map a persisted attack status to a runner control signal (pure).

    A ``cancelled`` status is the kill-switch (drop immediately); ``paused``
    holds the run; anything else continues. Used by the DB-backed control hook.
    """
    if status == STATUS_CANCELLED:
        return AttackControl.CANCEL
    if status == STATUS_PAUSED:
        return AttackControl.PAUSE
    return AttackControl.CONTINUE


def _payloads_dir() -> Path:
    """Locate the signed payload catalog directory (``backend/config/payloads``)."""
    return Path(__file__).resolve().parents[3] / "config" / "payloads"


def materialize_payload_sets(
    payload_config: dict[str, Any] | None,
    *,
    builder: PayloadBuilder,
) -> tuple[list[list[bytes]], list[str]]:
    """Materialise ``payload_config`` references into concrete byte payload sets.

    ``payload_config`` shape::

        {"sets": [{"family_id": "...", "encoding_pipeline": "...",
                   "parameters": {...}, "max_payloads": 64,
                   "approval_id": "...", "correlation_key": "..."}, ...]}

    Returns ``(payload_sets, labels)`` where ``labels`` reference the source
    registry entry (``<family_id>#<entry_id>``) for the first set — never the
    raw payload value. Raises :class:`ValueError` for a malformed config.
    """
    if not payload_config or not isinstance(payload_config.get("sets"), list):
        raise ValueError("payload_config.sets must be a non-empty list")
    raw_sets: list[dict[str, Any]] = payload_config["sets"]
    if not raw_sets:
        raise ValueError("payload_config.sets must be a non-empty list")

    payload_sets: list[list[bytes]] = []
    labels: list[str] = []
    for spec in raw_sets:
        request = PayloadBuildRequest(
            family_id=spec["family_id"],
            correlation_key=spec.get("correlation_key", spec["family_id"]),
            encoding_pipeline=spec.get("encoding_pipeline"),
            approval_id=spec.get("approval_id"),
            parameters=spec.get("parameters", {}),
            max_payloads=spec.get("max_payloads", 64),
        )
        bundle = builder.build(request)
        payload_sets.append([p.payload.encode("utf-8") for p in bundle.payloads])
        if not labels:  # sniper / battering-ram map the first set by ordinal
            labels = [f"{bundle.family_id}#{p.id}" for p in bundle.payloads]
    return payload_sets, labels


async def _execute(tenant_id: str, attack_id: str) -> dict[str, Any]:
    """Async body of the task (own engine/session bound to this loop)."""
    engine, session_factory = create_task_engine_and_session()
    repository = IntruderRepository()
    projects = WorkbenchProjectRepository()

    def _control_hook() -> AttackControl:
        # Poll the persisted status on a fresh short-lived session so an
        # operator pause/cancel (a status write via the API) is observed.
        async def _read() -> str | None:
            async with session_factory() as poll_session:
                await set_session_tenant(poll_session, tenant_id)
                return await repository.read_status(poll_session, tenant_id, attack_id)

        return control_from_status(_run_coro_in_thread(_read()))

    try:
        async with session_factory() as session:
            await set_session_tenant(session, tenant_id)
            attack = await repository.get_attack(session, tenant_id, attack_id)
            if attack is None:
                raise ValueError(f"attack {attack_id!r} not found")
            project = await projects.get(session, tenant_id, attack.project_id)
            if project is None:
                raise ValueError("project not found")
            if project.status is not ProjectStatus.ACTIVE:
                # Kill-switch: never run against a paused/archived project.
                await repository.save_progress(
                    session,
                    tenant_id,
                    attack_id,
                    status=STATUS_FAILED,
                    error_reason="project_not_active",
                )
                await session.commit()
                return {"attack_id": attack_id, "status": STATUS_FAILED}

            registry = PayloadRegistry(payloads_dir=_payloads_dir())
            registry.load()
            builder = PayloadBuilder(registry)
            payload_sets, labels = materialize_payload_sets(attack.payload_config, builder=builder)

            scope_service = ProjectScopeService(project.scope_rules)
            service = IntruderService(repository, sender=HttpxSender(), control_hook=_control_hook)
            summary = await service.run_attack(
                session,
                tenant_id,
                attack_id,
                scope_service=scope_service,
                payload_sets=payload_sets,
                payload_labels=labels,
            )
            await session.commit()
            return {
                "attack_id": attack_id,
                "status": summary.status,
                "forwarded": summary.forwarded,
                "blocked": summary.blocked,
                "flagged": summary.flagged,
            }
    finally:
        await engine.dispose()


@app.task(name=TASK_NAME, bind=True, max_retries=0)
def run_intruder_attack(
    self: Any, tenant_id: str, attack_id: str
) -> dict[str, Any]:  # noqa: ARG001
    """Celery entrypoint — execute (or resume) an attack. See module docstring."""
    try:
        return asyncio.run(_execute(tenant_id, attack_id))
    except Exception:
        # Never leak internals to a caller; the structured log carries context.
        logger.exception(
            "wb.intruder.run_failed",
            extra={"event": "wb.intruder.run_failed", "attack_id": attack_id},
        )
        raise


__all__ = [
    "TASK_NAME",
    "control_from_status",
    "materialize_payload_sets",
    "run_intruder_attack",
]
