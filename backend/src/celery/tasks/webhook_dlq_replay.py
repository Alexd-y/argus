"""T40 (Cycle 6 Batch 5, ARG-053) — daily Celery beat task replaying DLQ entries.

Schedule
--------
Registered as ``argus.notifications.webhook_dlq_replay`` in
:mod:`src.celery.beat_schedule`. Fires daily at 06:00 UTC (one hour after
``argus.intel.kev_refresh`` so a single beat container can sequence them on a
single core without contention).

Loop body
---------
1. :func:`list_due_for_replay` -> N pending rows whose ``next_retry_at <= now``
   (limit :data:`REPLAY_BATCH_LIMIT`).
2. For each row:
   a. Reconstruct :class:`NotificationEvent` from the persisted ``payload_json``.
   b. Build a fresh adapter via :func:`_build_adapter` so this replay never
      inherits dispatcher-side circuit-breaker / dedup state. Mirrors the
      operator-driven replay in :mod:`src.api.routers.admin_webhook_dlq`.
   c. Dispatch via :meth:`NotifierBase.send_with_retry`.
   d. ``delivered=True``  -> :func:`mark_replayed`   (terminal).
   e. ``delivered=False`` -> :func:`increment_attempt` (recompute next_retry_at).
   f. Adapter is always closed via ``await adapter.aclose()`` in a ``finally``.
3. :func:`list_abandoned_candidates` -> M aged rows (>= :data:`DLQ_MAX_AGE_DAYS`).
4. Each: :func:`mark_abandoned` with ``reason="max_age"``.
5. Return ``{"replayed": N, "failed": M, "abandoned_max_age": K}``.

Per-row failures NEVER bubble to the task body — they are caught, logged with
structured context (``argus_event="webhook_dlq_replay_row_error"``), counted as
failures, and the loop continues so a single broken row cannot poison the
whole tick.

Engine lifecycle
----------------
The task creates its own engine via :func:`create_task_engine_and_session`
(canonical Celery pattern in this repo — see ``src/scheduling/scan_trigger.py``
and ``src/celery/tasks/intel_refresh.py``) and disposes it on exit so asyncpg's
event-loop binding does not leak across Celery executions.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime
from typing import Any, Final

from sqlalchemy.ext.asyncio import AsyncSession

from src.celery_app import app
from src.db.models import WebhookDlqEntry
from src.db.session import create_task_engine_and_session
from src.mcp.services.notifications._base import NotifierBase
from src.mcp.services.notifications.jira import JiraAdapter
from src.mcp.services.notifications.linear import LinearAdapter
from src.mcp.services.notifications.schemas import (
    AdapterResult,
    NotificationEvent,
)
from src.mcp.services.notifications.slack import SlackNotifier
from src.mcp.services.notifications.webhook_dlq_persistence import (
    AlreadyTerminalError,
    DlqEntryNotFoundError,
    increment_attempt,
    list_abandoned_candidates,
    list_due_for_replay,
    mark_abandoned,
    mark_replayed,
)

logger = logging.getLogger(__name__)


REPLAY_BATCH_LIMIT: Final[int] = 100
ABANDON_BATCH_LIMIT: Final[int] = 100

#: Reason persisted on rows aged out beyond ``DLQ_MAX_AGE_DAYS``. Mirrors the
#: ``_VALID_ABANDONED_REASONS`` whitelist in
#: :mod:`src.mcp.services.notifications.webhook_dlq_persistence`.
_REASON_MAX_AGE: Final[str] = "max_age"

#: Closed-taxonomy short identifier used when a per-row dispatch raises an
#: exception that is not a recognised httpx transport error. Picked to be
#: distinct from the dispatcher-emitted ``error_code`` values so operators can
#: tell at a glance that the failure happened inside the beat task body
#: (typically: row-corruption or factory error) rather than upstream.
_DISPATCH_EXCEPTION_CODE: Final[str] = "dispatch_exception"

#: Closed-taxonomy fallback when the adapter returns ``delivered=False`` with
#: no populated ``error_code`` / ``skipped_reason`` (defensive — the production
#: ``NotifierBase`` always sets one or the other on a failed send).
_UNKNOWN_ERROR_CODE: Final[str] = "unknown_error"

#: Adapter factory used by :func:`_build_adapter`. Duplicated from the T39
#: admin router (``src/api/routers/admin_webhook_dlq.py``) on purpose — the
#: router's helper raises :class:`HTTPException` which is the wrong contract
#: for a Celery beat task, and importing the router into a beat-task module
#: would cross the API → background-task boundary the wrong way. Keep the two
#: factories in sync when adding a new adapter.
_ADAPTER_FACTORY: Final[dict[str, type[NotifierBase]]] = {
    SlackNotifier.name: SlackNotifier,
    LinearAdapter.name: LinearAdapter,
    JiraAdapter.name: JiraAdapter,
}


@app.task(  # type: ignore[untyped-decorator]  # Celery @app.task decorator is untyped upstream.
    name="argus.notifications.webhook_dlq_replay",
    bind=True,
    autoretry_for=(),
    queue="argus.notifications",
    max_retries=0,
)
def webhook_dlq_replay(self: Any) -> dict[str, int]:  # noqa: ARG001 — Celery bind=True signature
    """Sync wrapper for the async loop body (Celery task call shape).

    Mirrors the canonical async-in-Celery-sync pattern from
    :mod:`src.scheduling.scan_trigger`. The task body never raises — failures
    inside the loop are absorbed by :func:`_replay_entry`; failures setting up
    the engine surface as a structured error log and an empty counter dict.
    """
    try:
        return asyncio.run(_run())
    except Exception:
        logger.exception(
            "webhook_dlq_replay task body raised",
            extra={"argus_event": "webhook_dlq_replay_task_error"},
        )
        return {"replayed": 0, "failed": 0, "abandoned_max_age": 0}


async def _run(now: datetime | None = None) -> dict[str, int]:
    """Execute one beat tick.

    Parameters
    ----------
    now:
        Optional override for the current instant — primarily for deterministic
        tests. Production callers omit it and the task uses
        :func:`datetime.now` against UTC.
    """
    counts: dict[str, int] = {"replayed": 0, "failed": 0, "abandoned_max_age": 0}
    when = now if now is not None else datetime.now(UTC)

    engine, session_factory = create_task_engine_and_session()
    try:
        async with session_factory() as session:
            await _process_replay_batch(session, when=when, counts=counts)
            await _process_abandon_batch(session, when=when, counts=counts)
    finally:
        await engine.dispose()

    logger.info(
        "webhook_dlq_replay tick complete",
        extra={
            "argus_event": "webhook_dlq_replay_tick",
            "replayed": counts["replayed"],
            "failed": counts["failed"],
            "abandoned_max_age": counts["abandoned_max_age"],
        },
    )
    return counts


async def _process_replay_batch(
    session: AsyncSession,
    *,
    when: datetime,
    counts: dict[str, int],
) -> None:
    """Replay every row whose ``next_retry_at <= when`` (one batch)."""
    due_rows = await list_due_for_replay(session, now=when, limit=REPLAY_BATCH_LIMIT)
    for entry in due_rows:
        delivered = await _replay_entry(session, entry)
        counts["replayed" if delivered else "failed"] += 1
    await session.commit()


async def _process_abandon_batch(
    session: AsyncSession,
    *,
    when: datetime,
    counts: dict[str, int],
) -> None:
    """Abandon every row whose age >= :data:`DLQ_MAX_AGE_DAYS` (one batch)."""
    aged_rows = await list_abandoned_candidates(
        session, now=when, limit=ABANDON_BATCH_LIMIT
    )
    for entry in aged_rows:
        try:
            await mark_abandoned(
                session,
                entry_id=entry.id,
                tenant_id=entry.tenant_id,
                reason=_REASON_MAX_AGE,
            )
        except AlreadyTerminalError:
            # Race with operator-driven action between SELECT and UPDATE — safe
            # to skip; the row is already terminal in some other state.
            continue
        except DlqEntryNotFoundError:
            # Same race window: the row vanished (e.g. tenant DELETE CASCADE).
            continue
        except Exception:
            logger.exception(
                "webhook_dlq_replay row abandon failed",
                extra={
                    "argus_event": "webhook_dlq_replay_row_error",
                    "phase": "abandon",
                    "entry_id": entry.id,
                    "adapter_name": entry.adapter_name,
                },
            )
            continue
        counts["abandoned_max_age"] += 1
    await session.commit()


async def _replay_entry(session: AsyncSession, entry: WebhookDlqEntry) -> bool:
    """Replay a single DLQ row.

    Returns ``True`` iff the dispatch reported ``delivered=True``. Per-row
    failures (validation / factory error / transport exception) NEVER raise out
    of this helper — they are logged with structured context, the row is moved
    to ``increment_attempt``, and ``False`` is returned. The adapter is closed
    in a ``finally`` so its underlying httpx client is always released.
    """
    adapter: NotifierBase | None = None
    result: AdapterResult | None = None
    try:
        event = NotificationEvent.model_validate(entry.payload_json)
        adapter = _build_adapter(entry.adapter_name)
        result = await adapter.send_with_retry(event, tenant_id=entry.tenant_id)
    except Exception:
        logger.exception(
            "webhook_dlq_replay row dispatch failed",
            extra={
                "argus_event": "webhook_dlq_replay_row_error",
                "phase": "dispatch",
                "entry_id": entry.id,
                "adapter_name": entry.adapter_name,
            },
        )
        await _safe_increment_attempt(
            session,
            entry_id=entry.id,
            last_error_code=_DISPATCH_EXCEPTION_CODE,
            last_status_code=None,
        )
        return False
    finally:
        if adapter is not None:
            try:
                await adapter.aclose()
            except Exception:
                logger.warning(
                    "webhook_dlq_replay adapter aclose failed",
                    extra={
                        "argus_event": "webhook_dlq_replay_aclose_error",
                        "entry_id": entry.id,
                        "adapter_name": entry.adapter_name,
                    },
                )

    if result.delivered:
        try:
            await mark_replayed(
                session, entry_id=entry.id, tenant_id=entry.tenant_id
            )
        except AlreadyTerminalError:
            # Operator marked the row terminal between SELECT and UPDATE —
            # the dispatch already shipped, so we still count it as replayed.
            pass
        except DlqEntryNotFoundError:
            # Row vanished (e.g. tenant DELETE CASCADE) after dispatch — the
            # delivery is on-the-wire; counting it as replayed is the most
            # honest signal.
            pass
        return True

    error_code = result.error_code or result.skipped_reason or _UNKNOWN_ERROR_CODE
    await _safe_increment_attempt(
        session,
        entry_id=entry.id,
        last_error_code=error_code,
        last_status_code=result.status_code,
    )
    return False


async def _safe_increment_attempt(
    session: AsyncSession,
    *,
    entry_id: str,
    last_error_code: str,
    last_status_code: int | None,
) -> None:
    """Wrapper around :func:`increment_attempt` that swallows DAO-level races.

    The beat task is the only consumer of the failure path here; absorbing the
    closed-taxonomy DAO exceptions keeps the loop body straight-line.
    """
    try:
        await increment_attempt(
            session,
            entry_id=entry_id,
            last_error_code=last_error_code,
            last_status_code=last_status_code,
        )
    except (AlreadyTerminalError, DlqEntryNotFoundError):
        # Race with operator action between SELECT and UPDATE — safe to skip.
        return


def _build_adapter(adapter_name: str) -> NotifierBase:
    """Construct a fresh notification adapter by name.

    Each replay constructs a dedicated adapter so it never inherits long-lived
    dispatcher state (in-process circuit breaker, idempotency dedup bucket).
    Mirrors the operator-driven replay helper in
    :mod:`src.api.routers.admin_webhook_dlq` — keep the two factories in sync
    when adding a new adapter. Unknown ``adapter_name`` is a row-corruption
    signal and surfaces as :class:`ValueError` (caught by the per-row handler
    in :func:`_replay_entry`).
    """
    factory = _ADAPTER_FACTORY.get(adapter_name)
    if factory is None:
        raise ValueError(f"unknown adapter_name: {adapter_name!r}")
    return factory()


__all__ = [
    "ABANDON_BATCH_LIMIT",
    "REPLAY_BATCH_LIMIT",
    "_build_adapter",
    "_replay_entry",
    "_run",
    "webhook_dlq_replay",
]
