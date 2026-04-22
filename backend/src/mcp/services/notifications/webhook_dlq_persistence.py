"""Webhook DLQ persistence — DAO + lifecycle helpers (T38 / Cycle 6 Batch 5, ARG-053).

Co-located with the existing webhook adapters (`_base.py`, `dispatcher.py`,
`slack.py`) per plan deviation D-2 — the notification subsystem package
boundary lives at ``mcp/services/notifications/``, not at top-level
``notifications/``. See ``ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md``
§2 D-2.

Public surface
--------------
* Pure helper :func:`compute_next_retry_at` mirrors the exponential backoff
  shape of :func:`._base.compute_backoff_seconds` (base 30s, factor 4,
  cap 24h) but without jitter — daily beat replay does not benefit from
  jitter and jitter would obscure "why was row N not replayed" debugging.
* Async DAO :func:`enqueue` / :func:`mark_replayed` / :func:`mark_abandoned`
  / :func:`increment_attempt` / list helpers — caller owns the transaction
  boundary (no implicit ``commit``).
* Closed-taxonomy DAO exceptions :exc:`DlqEntryNotFoundError` and
  :exc:`AlreadyTerminalError` map to ``WEBHOOK_DLQ_FAILURE_TAXONOMY``
  HTTP codes in the T39 admin router.

Cross-tenant probe protection
-----------------------------
``get_by_id`` / ``mark_*`` accept ``tenant_id=None`` to mean
"super-admin cross-tenant lookup". Admin callers (with concrete
``tenant_id``) that target a row belonging to another tenant receive
``DlqEntryNotFoundError`` — never a distinct "forbidden" — to prevent
existence leakage via the discriminator status code.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any, Final

from sqlalchemy import asc, desc, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.sql.elements import ColumnElement

from src.db.models import WebhookDlqEntry, gen_uuid
from src.mcp.services.notifications._base import hash_target

# ---------------------------------------------------------------------------
# Backoff bounds — mirror _base.py shape so audit/replay logs share scale.
# Base 30s × factor 4 ^ attempt, capped at 24h; no jitter (the daily beat
# replay does not benefit from jitter, and jitter would obscure "why was
# row N not replayed at the expected instant?" debugging).
# ---------------------------------------------------------------------------

DLQ_BACKOFF_BASE_SECONDS: Final[float] = 30.0
DLQ_BACKOFF_FACTOR: Final[float] = 4.0
DLQ_BACKOFF_CAP_SECONDS: Final[float] = 24 * 3600.0
DLQ_MAX_AGE_DAYS: Final[int] = 14

# Closed-taxonomy whitelists enforced at the DAO boundary so the T39 admin
# router and T40 beat task can rely on a small known set without re-validating.
_VALID_LIST_STATUSES: Final[frozenset[str]] = frozenset(
    {"pending", "replayed", "abandoned"}
)
_VALID_ABANDONED_REASONS: Final[frozenset[str]] = frozenset(
    {"operator", "max_age", "manual_abandon"}
)


# ---------------------------------------------------------------------------
# Closed-taxonomy DAO exceptions — T39 router maps these to
# ``WEBHOOK_DLQ_FAILURE_TAXONOMY`` HTTP codes without leaking internals.
# Both inherit straight from ``Exception`` and accept the standard optional
# message argument; the docstring is the canonical contract.
# ---------------------------------------------------------------------------


class DlqEntryNotFoundError(Exception):
    """Raised when a row is missing OR belongs to another tenant.

    The DAO collapses both cases into a single error so the cross-tenant
    existence side channel stays closed: an admin scoped to tenant A
    cannot enumerate tenant-B entry ids by observing 404 vs 403 on
    :func:`mark_replayed` / :func:`mark_abandoned` / :func:`get_by_id`.
    """


class AlreadyTerminalError(Exception):
    """Raised when a caller tries to mutate a terminal entry.

    Terminal = ``replayed_at`` or ``abandoned_at`` is set. The DAO
    enforces single-mutation semantics so the audit chain stays
    deterministic and double-replay or replay-after-abandon is impossible.
    """


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _utcnow() -> datetime:
    """Return the current UTC-aware instant (helper for monkeypatching)."""
    return datetime.now(UTC)


def compute_next_retry_at(
    *, attempt_count: int, now: datetime | None = None
) -> datetime:
    """Return the UTC-aware instant for the next replay attempt.

    Mirrors :func:`._base.compute_backoff_seconds` shape (base 30s,
    factor 4, cap 24h) but without jitter — daily beat replay does not
    benefit from jitter and jitter would obscure "why was row N not
    replayed at the expected instant?" debugging.

    Parameters
    ----------
    attempt_count:
        Number of attempts that have already failed (>= 0). The next
        retry uses ``base * factor**attempt_count`` capped at 24 hours.
    now:
        Optional override for "the current instant" — primarily for
        deterministic tests. When ``None``, :func:`_utcnow` is used.
    """
    if attempt_count < 0:
        raise ValueError("attempt_count must be >= 0")
    delay = min(
        DLQ_BACKOFF_CAP_SECONDS,
        DLQ_BACKOFF_BASE_SECONDS * (DLQ_BACKOFF_FACTOR**attempt_count),
    )
    base = now if now is not None else _utcnow()
    return base + timedelta(seconds=delay)


# ---------------------------------------------------------------------------
# Internal DAO helpers
# ---------------------------------------------------------------------------


async def _load_for_mutation(
    session: AsyncSession, *, entry_id: str, tenant_id: str | None
) -> WebhookDlqEntry:
    """Fetch a row by id, scoped by tenant when ``tenant_id`` is provided.

    Raises :exc:`DlqEntryNotFoundError` for both true misses and
    cross-tenant probes (admin scoped to A targeting a row in B). The
    ``tenant_id=None`` projection is the super-admin cross-tenant lookup.
    """
    stmt = select(WebhookDlqEntry).where(WebhookDlqEntry.id == entry_id)
    if tenant_id is not None:
        stmt = stmt.where(WebhookDlqEntry.tenant_id == tenant_id)
    row = (await session.scalars(stmt)).first()
    if row is None:
        raise DlqEntryNotFoundError(
            f"webhook DLQ entry {entry_id!r} not found"
        )
    return row


def _build_list_filters(
    *,
    tenant_id: str | None,
    status: str | None,
    adapter_name: str | None,
    created_after: datetime | None,
    created_before: datetime | None,
) -> list[ColumnElement[bool]]:
    """Translate the :func:`list_for_tenant` filter knobs into SQL clauses.

    ``status`` MUST already be validated against :data:`_VALID_LIST_STATUSES`
    by the caller — we trust the input here to keep the helper trivially
    testable in isolation.
    """
    filters: list[ColumnElement[bool]] = []
    if tenant_id is not None:
        filters.append(WebhookDlqEntry.tenant_id == tenant_id)
    if adapter_name is not None:
        filters.append(WebhookDlqEntry.adapter_name == adapter_name)
    if created_after is not None:
        filters.append(WebhookDlqEntry.created_at >= created_after)
    if created_before is not None:
        filters.append(WebhookDlqEntry.created_at <= created_before)
    if status == "pending":
        filters.append(WebhookDlqEntry.replayed_at.is_(None))
        filters.append(WebhookDlqEntry.abandoned_at.is_(None))
    elif status == "replayed":
        filters.append(WebhookDlqEntry.replayed_at.is_not(None))
    elif status == "abandoned":
        filters.append(WebhookDlqEntry.abandoned_at.is_not(None))
    return filters


# ---------------------------------------------------------------------------
# Public DAO surface
# ---------------------------------------------------------------------------


async def enqueue(
    session: AsyncSession,
    *,
    tenant_id: str,
    adapter_name: str,
    event_type: str,
    event_id: str,
    target_url: str,
    payload: dict[str, Any],
    last_error_code: str,
    last_status_code: int | None,
    attempt_count: int,
) -> WebhookDlqEntry:
    """Persist a failed-after-retry webhook delivery into the DLQ.

    ``target_url`` is hashed via :func:`._base.hash_target` BEFORE storage;
    the raw URL (which carries the secret webhook token) is NEVER persisted.
    ``payload`` is stored verbatim in ``payload_json`` so the T40 daily
    beat replay can re-issue the original delivery byte-for-byte.

    Parameters
    ----------
    payload:
        Original webhook body. ``dict[str, Any]`` matches the ORM column
        type ``Mapped[dict[str, Any]]`` — the ``Any`` value type is
        unavoidable because adapter-specific payload shapes (Slack Block
        Kit / Linear GraphQL / Jira REST) cannot be unified at the DAO
        boundary.

    Idempotency
    -----------
    The unique key is ``(tenant_id, adapter_name, event_id)``. A second
    enqueue for the same logical delivery is a no-op: the
    :exc:`IntegrityError` is rolled back and the existing row is
    returned. Callers therefore cannot rely on object identity to detect
    duplicates — inspect ``returned.attempt_count`` instead.
    """
    entry = WebhookDlqEntry(
        id=gen_uuid(),
        tenant_id=tenant_id,
        adapter_name=adapter_name,
        event_type=event_type,
        event_id=event_id,
        target_url_hash=hash_target(target_url),
        payload_json=payload,
        last_error_code=last_error_code,
        last_status_code=last_status_code,
        attempt_count=attempt_count,
        next_retry_at=compute_next_retry_at(attempt_count=attempt_count),
    )
    session.add(entry)
    try:
        await session.flush()
    except IntegrityError:
        await session.rollback()
        existing = await get_by_event(
            session,
            tenant_id=tenant_id,
            adapter_name=adapter_name,
            event_id=event_id,
        )
        if existing is None:
            # Race: the conflicting row was deleted between our flush
            # failure and the follow-up read. Re-raise so the caller can
            # decide whether to retry — silently swallowing here would
            # break the "always returns a row" idempotency contract.
            raise
        return existing
    return entry


async def get_by_id(
    session: AsyncSession, *, entry_id: str, tenant_id: str | None = None
) -> WebhookDlqEntry | None:
    """Fetch a single entry by id, optionally scoped to ``tenant_id``.

    ``tenant_id=None`` means "super-admin cross-tenant lookup". When a
    concrete ``tenant_id`` is supplied and the row belongs to another
    tenant, ``None`` is returned — matching a true miss — so the
    cross-tenant existence side channel stays closed.
    """
    stmt = select(WebhookDlqEntry).where(WebhookDlqEntry.id == entry_id)
    if tenant_id is not None:
        stmt = stmt.where(WebhookDlqEntry.tenant_id == tenant_id)
    return (await session.scalars(stmt)).first()


async def get_by_event(
    session: AsyncSession,
    *,
    tenant_id: str,
    adapter_name: str,
    event_id: str,
) -> WebhookDlqEntry | None:
    """Look up the entry for a logical delivery key.

    Used by :func:`enqueue` to recover from a UNIQUE-constraint violation
    on the idempotency tuple. Always tenant-scoped — the unique constraint
    is per-tenant and the lookup mirrors that contract.
    """
    stmt = select(WebhookDlqEntry).where(
        WebhookDlqEntry.tenant_id == tenant_id,
        WebhookDlqEntry.adapter_name == adapter_name,
        WebhookDlqEntry.event_id == event_id,
    )
    return (await session.scalars(stmt)).first()


async def list_for_tenant(
    session: AsyncSession,
    *,
    tenant_id: str | None,
    status: str | None = None,
    adapter_name: str | None = None,
    created_after: datetime | None = None,
    created_before: datetime | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[Sequence[WebhookDlqEntry], int]:
    """Paginated list of DLQ entries plus the total count for the filter.

    Backs the T39 ``GET /admin/webhooks/dlq`` endpoint.

    Parameters
    ----------
    tenant_id:
        ``None`` projects across all tenants (super-admin only); a
        concrete value scopes the query to that tenant.
    status:
        One of ``"pending"`` / ``"replayed"`` / ``"abandoned"``; ``None``
        matches every row. ``"pending"`` excludes both terminal columns.
    adapter_name, created_after, created_before:
        Optional refinement filters; all combine via AND.
    limit, offset:
        Standard pagination knobs. Caller is expected to validate ranges.
    """
    if status is not None and status not in _VALID_LIST_STATUSES:
        raise ValueError(f"invalid status filter: {status!r}")

    filters = _build_list_filters(
        tenant_id=tenant_id,
        status=status,
        adapter_name=adapter_name,
        created_after=created_after,
        created_before=created_before,
    )

    count_stmt = select(func.count()).select_from(WebhookDlqEntry).where(*filters)
    total = int((await session.execute(count_stmt)).scalar_one())

    stmt = (
        select(WebhookDlqEntry)
        .where(*filters)
        .order_by(desc(WebhookDlqEntry.created_at), asc(WebhookDlqEntry.id))
        .offset(offset)
        .limit(limit)
    )
    rows = (await session.scalars(stmt)).all()
    return rows, total


async def list_due_for_replay(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> Sequence[WebhookDlqEntry]:
    """Fetch entries whose ``next_retry_at <= now`` and not yet terminal.

    Ordered ``created_at ASC`` (FIFO) so the T40 daily beat processes the
    oldest pending deliveries first.
    """
    moment = now if now is not None else _utcnow()
    stmt = (
        select(WebhookDlqEntry)
        .where(
            WebhookDlqEntry.next_retry_at <= moment,
            WebhookDlqEntry.abandoned_at.is_(None),
            WebhookDlqEntry.replayed_at.is_(None),
        )
        .order_by(asc(WebhookDlqEntry.created_at))
        .limit(limit)
    )
    return (await session.scalars(stmt)).all()


async def list_abandoned_candidates(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 100,
) -> Sequence[WebhookDlqEntry]:
    """Fetch entries whose age >= :data:`DLQ_MAX_AGE_DAYS` and not terminal.

    The T40 daily beat sweeps these into ``abandoned`` with
    ``reason="max_age"``. Ordered ``created_at ASC`` so the oldest
    candidates expire first if the limit is hit.
    """
    moment = now if now is not None else _utcnow()
    cutoff = moment - timedelta(days=DLQ_MAX_AGE_DAYS)
    stmt = (
        select(WebhookDlqEntry)
        .where(
            WebhookDlqEntry.created_at <= cutoff,
            WebhookDlqEntry.abandoned_at.is_(None),
            WebhookDlqEntry.replayed_at.is_(None),
        )
        .order_by(asc(WebhookDlqEntry.created_at))
        .limit(limit)
    )
    return (await session.scalars(stmt)).all()


async def mark_replayed(
    session: AsyncSession,
    *,
    entry_id: str,
    tenant_id: str | None,
) -> WebhookDlqEntry:
    """Set ``replayed_at = utcnow()`` (terminal).

    Raises :exc:`DlqEntryNotFoundError` for a missing or cross-tenant row.
    Raises :exc:`AlreadyTerminalError` when ``replayed_at`` or
    ``abandoned_at`` is already set — guarantees single-mutation
    semantics so the audit chain stays deterministic.
    """
    entry = await _load_for_mutation(
        session, entry_id=entry_id, tenant_id=tenant_id
    )
    if entry.replayed_at is not None or entry.abandoned_at is not None:
        raise AlreadyTerminalError(
            f"webhook DLQ entry {entry_id!r} is already terminal"
        )
    entry.replayed_at = _utcnow()
    await session.flush()
    return entry


async def mark_abandoned(
    session: AsyncSession,
    *,
    entry_id: str,
    tenant_id: str | None,
    reason: str,
) -> WebhookDlqEntry:
    """Set ``abandoned_at`` and ``abandoned_reason`` (terminal).

    ``reason`` MUST be one of ``"operator"`` / ``"max_age"`` /
    ``"manual_abandon"`` — :exc:`ValueError` otherwise. The same
    :exc:`DlqEntryNotFoundError` / :exc:`AlreadyTerminalError` semantics
    as :func:`mark_replayed` apply.
    """
    if reason not in _VALID_ABANDONED_REASONS:
        raise ValueError(f"invalid abandoned_reason: {reason!r}")
    entry = await _load_for_mutation(
        session, entry_id=entry_id, tenant_id=tenant_id
    )
    if entry.replayed_at is not None or entry.abandoned_at is not None:
        raise AlreadyTerminalError(
            f"webhook DLQ entry {entry_id!r} is already terminal"
        )
    entry.abandoned_at = _utcnow()
    entry.abandoned_reason = reason
    await session.flush()
    return entry


async def increment_attempt(
    session: AsyncSession,
    *,
    entry_id: str,
    last_error_code: str,
    last_status_code: int | None,
) -> WebhookDlqEntry:
    """Bump ``attempt_count`` after a replay failure and recompute the backoff.

    No tenant filter — the caller is the T40 beat task that already holds
    a trusted entry id pulled from :func:`list_due_for_replay`. Raises
    :exc:`DlqEntryNotFoundError` if the row vanished between selection
    and update (e.g. concurrent admin abandon).
    """
    stmt = select(WebhookDlqEntry).where(WebhookDlqEntry.id == entry_id)
    entry = (await session.scalars(stmt)).first()
    if entry is None:
        raise DlqEntryNotFoundError(
            f"webhook DLQ entry {entry_id!r} not found"
        )
    entry.attempt_count = entry.attempt_count + 1
    entry.last_error_code = last_error_code
    entry.last_status_code = last_status_code
    entry.next_retry_at = compute_next_retry_at(attempt_count=entry.attempt_count)
    await session.flush()
    return entry


__all__ = [
    "DLQ_BACKOFF_BASE_SECONDS",
    "DLQ_BACKOFF_CAP_SECONDS",
    "DLQ_BACKOFF_FACTOR",
    "DLQ_MAX_AGE_DAYS",
    "AlreadyTerminalError",
    "DlqEntryNotFoundError",
    "compute_next_retry_at",
    "enqueue",
    "get_by_event",
    "get_by_id",
    "increment_attempt",
    "list_abandoned_candidates",
    "list_due_for_replay",
    "list_for_tenant",
    "mark_abandoned",
    "mark_replayed",
]
