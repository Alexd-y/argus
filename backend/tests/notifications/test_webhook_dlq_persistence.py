"""T38 / ARG-053 — webhook DLQ persistence DAO unit tests.

Covers acceptance criteria (a)-(f) from the Cycle 6 Batch 5 plan
(``ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md`` §5 / T38) for
:mod:`src.mcp.services.notifications.webhook_dlq_persistence`.

Test architecture
-----------------
Each test gets a fresh in-memory async SQLite engine (``aiosqlite``) seeded
with a minimal ``tenants`` table, then has migration 027 applied via the
:class:`MigrationContext` + :class:`Operations` pattern from the migration
smoke suite (``test_webhook_dlq_migration`` Layer A). This guarantees the
DAO is exercised against the production migration schema (not an ORM
``create_all`` shortcut), so any drift between migration 027 and the
``WebhookDlqEntry`` ORM surface fails here too.

Determinism
-----------
Wall-clock time is pinned via ``monkeypatch.setattr`` on the module-level
:func:`_utcnow` helper (the DAO routes every "current instant" read through
that single seam — see the docstring on
``webhook_dlq_persistence._utcnow``). No ``time.sleep`` calls anywhere; no
real network; no real DB beyond local SQLite.

SQLite vs. Postgres datetime caveat
-----------------------------------
``DateTime(timezone=True)`` columns are stored as naive datetimes by the
SQLite dialect — read-back returns a naive ``datetime``. Assertions strip
``tzinfo`` from the expected (UTC-aware) value before comparison via
:func:`_naive`. Postgres correctness is verified separately by the RLS
smoke suite (``test_webhook_dlq_rls`` under the migration test tree).

Bucket coverage (sums to 22 — the plan headline of "18" is a known
arithmetic typo; 5+4+3+4+6=22 cases match the per-bucket detailed
breakdown):

* ``compute_next_retry_at`` — 5 cases (backoff math + ``ValueError``).
* ``enqueue``                — 4 cases (happy / idempotent / multi-tenant /
  payload round-trip).
* ``get_by_id`` / ``get_by_event`` — 3 cases (super-admin, cross-tenant
  probe, by-event lookup).
* ``list_for_tenant`` / ``list_due_for_replay`` /
  ``list_abandoned_candidates`` — 4 cases (pagination, status filter, FIFO
  cutoff, 14d age cutoff).
* ``mark_replayed`` / ``mark_abandoned`` / ``increment_attempt`` — 6 cases
  (happy paths, ``AlreadyTerminalError``, ``ValueError`` on bad reason,
  cross-tenant probe, attempt-count + backoff bump).
"""

from __future__ import annotations

import importlib.util
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import event, func, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from src.db.models import WebhookDlqEntry
from src.mcp.services.notifications._base import hash_target
from src.mcp.services.notifications.webhook_dlq_persistence import (
    DLQ_BACKOFF_BASE_SECONDS,
    DLQ_BACKOFF_CAP_SECONDS,
    DLQ_BACKOFF_FACTOR,
    DLQ_MAX_AGE_DAYS,
    AlreadyTerminalError,
    DlqEntryNotFoundError,
    compute_next_retry_at,
    enqueue,
    get_by_event,
    get_by_id,
    increment_attempt,
    list_abandoned_candidates,
    list_due_for_replay,
    list_for_tenant,
    mark_abandoned,
    mark_replayed,
)

# ---------------------------------------------------------------------------
# Constants — every magic value lives here so a future schema bump is a
# single-line edit at the top of the module.
# ---------------------------------------------------------------------------

_DAO_MODULE: str = "src.mcp.services.notifications.webhook_dlq_persistence"
_BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]
_VERSIONS_DIR: Path = _BACKEND_ROOT / "alembic" / "versions"
_REVISION: str = "027"

# Pinned "current instant" for every monkeypatched test — far enough from
# any creation timestamp that ``next_retry_at`` arithmetic stays distinct
# from ``created_at`` (server-default ``CURRENT_TIMESTAMP``) on assertion.
_FIXED_NOW: datetime = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Schema-bootstrap helpers — mirror the SQLite isolation pattern from the
# ``test_webhook_dlq_migration`` Layer A in the migration smoke suite.
# ---------------------------------------------------------------------------


def _load_revision_module() -> Any:
    """Import revision 027 as a standalone module (no full Alembic chain run).

    Returning ``Any`` is deliberate: ``upgrade()`` / ``downgrade()`` are
    free functions on the migration script and have no public type stubs.
    The full migration chain contains JSONB / PG-specific ops that SQLite
    cannot compile, so a vanilla ``command.upgrade(cfg, "head")`` against
    SQLite is not viable — we apply ONLY revision 027 against a clean
    schema.
    """
    matches = list(_VERSIONS_DIR.glob(f"{_REVISION}_*.py"))
    assert matches, f"revision file for {_REVISION} not found under {_VERSIONS_DIR}"
    spec = importlib.util.spec_from_file_location(f"_alembic_{_REVISION}", matches[0])
    assert spec is not None and spec.loader is not None, (
        f"unable to build importlib spec for {matches[0]}"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bootstrap_schema_sync(conn: Any) -> None:
    """Create the minimal ``tenants`` table and apply revision 027.

    Called via ``AsyncConnection.run_sync`` so the migration's synchronous
    Alembic operations run against the bound sync DB-API connection.
    """
    conn.execute(
        text(
            "CREATE TABLE tenants ("
            "id VARCHAR(36) PRIMARY KEY, "
            "name VARCHAR(255) NOT NULL"
            ")"
        )
    )
    module = _load_revision_module()
    ctx = MigrationContext.configure(conn)
    with Operations.context(ctx):
        module.upgrade()


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """Per-test in-memory async SQLite engine with the DLQ schema applied.

    ``StaticPool`` is required so every checkout shares the same DB-API
    connection — without it the ``:memory:`` database evaporates between
    transactions. ``PRAGMA foreign_keys=ON`` is registered as a connect
    listener so the ``ON DELETE CASCADE`` clause from migration 027 is
    actually enforced.
    """
    eng = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )

    @event.listens_for(eng.sync_engine, "connect")
    def _enable_sqlite_fk(dbapi_conn: Any, _conn_record: Any) -> None:
        cursor = dbapi_conn.cursor()
        try:
            cursor.execute("PRAGMA foreign_keys=ON")
        finally:
            cursor.close()

    async with eng.begin() as conn:
        await conn.run_sync(_bootstrap_schema_sync)

    try:
        yield eng
    finally:
        await eng.dispose()


@pytest.fixture
async def session(engine: AsyncEngine) -> AsyncIterator[AsyncSession]:
    """Per-test ``AsyncSession`` with ``expire_on_commit=False``.

    ``expire_on_commit=False`` keeps mapped attributes addressable after the
    test commits — without it every assertion right after ``session.commit()``
    would trigger a lazy refresh and either re-fetch from SQLite (fine) or
    fail because the test has moved on. Mirrors the EPSS persistence test
    fixture style.
    """
    sm = async_sessionmaker(engine, expire_on_commit=False)
    async with sm() as s:
        try:
            yield s
        finally:
            await s.rollback()


@pytest.fixture
def freeze_now(monkeypatch: pytest.MonkeyPatch) -> datetime:
    """Pin ``webhook_dlq_persistence._utcnow`` to :data:`_FIXED_NOW`.

    Returns the frozen instant so tests can assert against it without
    re-importing the constant.
    """
    monkeypatch.setattr(f"{_DAO_MODULE}._utcnow", lambda: _FIXED_NOW)
    return _FIXED_NOW


# ---------------------------------------------------------------------------
# Helpers used by multiple tests.
# ---------------------------------------------------------------------------


async def _seed_tenant(session: AsyncSession, name: str) -> str:
    """Insert a minimal ``tenants`` row and return the new id."""
    tid = str(uuid.uuid4())
    await session.execute(
        text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
        {"id": tid, "name": name},
    )
    await session.commit()
    return tid


async def _enqueue_default(
    session: AsyncSession,
    *,
    tenant_id: str,
    adapter_name: str = "slack",
    event_type: str = "finding.created",
    event_id: str = "evt-default",
    target_url: str = "https://hooks.slack.example/T0/B0/secret",
    payload: dict[str, Any] | None = None,
    last_error_code: str = "http_5xx",
    last_status_code: int | None = 503,
    attempt_count: int = 0,
) -> WebhookDlqEntry:
    """Convenience wrapper around :func:`enqueue` with safe defaults."""
    return await enqueue(
        session,
        tenant_id=tenant_id,
        adapter_name=adapter_name,
        event_type=event_type,
        event_id=event_id,
        target_url=target_url,
        payload=payload if payload is not None else {"k": "v"},
        last_error_code=last_error_code,
        last_status_code=last_status_code,
        attempt_count=attempt_count,
    )


async def _force_created_at(
    session: AsyncSession, *, entry_id: str, when: datetime
) -> None:
    """Backdate / forward-date ``created_at`` for a specific row.

    ``created_at`` uses ``server_default=func.now()`` so the DAO never
    accepts an explicit value — needed for the FIFO and 14-day cutoff
    tests that depend on a specific creation instant.
    """
    await session.execute(
        text("UPDATE webhook_dlq_entries SET created_at = :ts WHERE id = :id"),
        {"ts": _naive(when), "id": entry_id},
    )
    await session.commit()


def _naive(dt: datetime) -> datetime:
    """Strip ``tzinfo`` so SQLite-readback comparisons line up.

    SQLite's ``DateTime(timezone=True)`` round-trips into naive datetimes —
    an aware-vs-naive comparison raises ``TypeError``, so all expected
    values are stripped before assertion.
    """
    return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt


# ===========================================================================
# Bucket 1 — ``compute_next_retry_at`` (5 cases).
# Pure helper; no DB / fixture / async needed.
# ===========================================================================


def test_compute_next_retry_at_attempt_zero_is_thirty_seconds() -> None:
    """``attempt_count=0`` -> base delay (30s) — acceptance criterion (c)."""
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    got = compute_next_retry_at(attempt_count=0, now=base)
    assert got == base + timedelta(seconds=DLQ_BACKOFF_BASE_SECONDS)
    assert got - base == timedelta(seconds=30.0)


def test_compute_next_retry_at_attempt_one_is_one_twenty_seconds() -> None:
    """``attempt_count=1`` -> 30 * 4 = 120s — acceptance criterion (c)."""
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    got = compute_next_retry_at(attempt_count=1, now=base)
    expected_delay = DLQ_BACKOFF_BASE_SECONDS * DLQ_BACKOFF_FACTOR
    assert got - base == timedelta(seconds=expected_delay)
    assert got - base == timedelta(seconds=120.0)


def test_compute_next_retry_at_attempt_four_is_seventy_six_eighty_seconds() -> None:
    """``attempt_count=4`` -> 30 * 4^4 = 7680s — acceptance criterion (c)."""
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    got = compute_next_retry_at(attempt_count=4, now=base)
    expected_delay = DLQ_BACKOFF_BASE_SECONDS * (DLQ_BACKOFF_FACTOR**4)
    assert got - base == timedelta(seconds=expected_delay)
    assert got - base == timedelta(seconds=7680.0)


def test_compute_next_retry_at_high_attempt_capped_at_twenty_four_hours() -> None:
    """``attempt_count=20`` -> capped at 86400s — acceptance criterion (c).

    30 * 4^20 = ~3.3e13 seconds without the cap; the DAO must clamp to
    24h so an exhausted entry doesn't drift to a "next replay in year
    3000" timestamp that would silently drop it from every replay sweep.
    """
    base = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    got = compute_next_retry_at(attempt_count=20, now=base)
    assert got - base == timedelta(seconds=DLQ_BACKOFF_CAP_SECONDS)
    assert got - base == timedelta(hours=24)


def test_compute_next_retry_at_negative_attempt_raises_value_error() -> None:
    """Negative ``attempt_count`` -> ``ValueError`` (defensive guard)."""
    with pytest.raises(ValueError, match="attempt_count must be >= 0"):
        compute_next_retry_at(attempt_count=-1)


# ===========================================================================
# Bucket 2 — ``enqueue`` (4 cases).
# ===========================================================================


async def test_enqueue_happy_path_persists_hashed_target_and_first_backoff(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """Acceptance criterion (a) — raw URL never persisted; +30s backoff.

    The webhook URL embeds the secret bot token (Slack hooks, Linear
    GraphQL bearer, Jira API token); persisting the raw URL would bypass
    the existing redaction guard in ``_base.py``. Verifies the DAO uses
    ``hash_target`` for storage and that the first attempt's backoff is
    the base 30s.
    """
    tenant_id = await _seed_tenant(session, "happy-path-tenant")
    raw_url = "https://hooks.slack.example/T0/B0/super-secret-token"

    entry = await _enqueue_default(
        session,
        tenant_id=tenant_id,
        event_id="evt-happy-1",
        target_url=raw_url,
        attempt_count=0,
    )
    await session.commit()

    assert entry.target_url_hash == hash_target(raw_url)
    assert raw_url not in entry.target_url_hash
    assert entry.next_retry_at == freeze_now + timedelta(
        seconds=DLQ_BACKOFF_BASE_SECONDS
    )
    assert entry.replayed_at is None
    assert entry.abandoned_at is None
    assert entry.attempt_count == 0


async def test_enqueue_idempotent_duplicate_returns_existing_row(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """Acceptance criterion (b) — re-enqueue is a no-op merge.

    Same ``(tenant_id, adapter_name, event_id)`` triple on a second call
    must NOT create a second row; the DAO catches the unique-constraint
    ``IntegrityError``, rolls back, and returns the existing row.
    """
    tenant_id = await _seed_tenant(session, "idem-tenant")
    first = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-dup", payload={"v": 1}
    )
    await session.commit()
    first_id = first.id

    second = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-dup", payload={"v": 2}
    )
    await session.commit()

    assert second.id == first_id, (
        "second enqueue must return the existing row, not a fresh one"
    )

    total = await session.scalar(
        select(func.count()).select_from(WebhookDlqEntry)
    )
    assert total == 1, f"only one row should exist, got {total}"


async def test_enqueue_multi_tenant_same_event_creates_distinct_rows(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """Same ``(adapter, event_id)`` under different tenants -> two rows.

    The unique constraint is per-tenant: tenant A and tenant B must each
    be able to log a delivery for the same logical event without colliding.
    """
    tenant_a = await _seed_tenant(session, "multi-tenant-a")
    tenant_b = await _seed_tenant(session, "multi-tenant-b")

    row_a = await _enqueue_default(
        session, tenant_id=tenant_a, event_id="evt-shared"
    )
    await session.commit()
    row_b = await _enqueue_default(
        session, tenant_id=tenant_b, event_id="evt-shared"
    )
    await session.commit()

    assert row_a.id != row_b.id
    total = await session.scalar(
        select(func.count()).select_from(WebhookDlqEntry)
    )
    assert total == 2

    rows = (
        await session.scalars(
            select(WebhookDlqEntry).order_by(WebhookDlqEntry.tenant_id)
        )
    ).all()
    tenant_ids = {r.tenant_id for r in rows}
    assert tenant_ids == {tenant_a, tenant_b}


async def test_enqueue_payload_round_trip_preserves_nested_structure(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """Complex nested ``payload`` survives serialise -> deserialise intact.

    The T40 daily beat replay re-issues the original delivery byte-for-byte
    — any silent JSON mutation here would change the webhook signature and
    break downstream HMAC verification.
    """
    tenant_id = await _seed_tenant(session, "payload-tenant")
    payload: dict[str, Any] = {
        "blocks": [
            {"type": "section", "text": {"type": "mrkdwn", "text": "*hi*"}},
            {"type": "divider"},
        ],
        "context": {
            "scan_id": "scan-001",
            "finding_ids": ["f-1", "f-2", "f-3"],
            "severity": {"label": "high", "score": 7.5},
        },
        "unicode": "тест-эмодзи",
        "nested": {"a": {"b": {"c": [1, 2, 3]}}},
        "null_field": None,
        "bool_flag": True,
    }

    entry = await _enqueue_default(
        session,
        tenant_id=tenant_id,
        event_id="evt-payload",
        payload=payload,
    )
    await session.commit()

    refetched = await get_by_id(session, entry_id=entry.id, tenant_id=tenant_id)
    assert refetched is not None
    assert refetched.payload_json == payload


# ===========================================================================
# Bucket 3 — ``get_by_id`` / ``get_by_event`` (3 cases).
# ===========================================================================


async def test_get_by_id_with_no_tenant_filter_returns_row(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """``tenant_id=None`` is the documented super-admin lookup.

    Used by T40's beat task and the T39 super-admin admin surface that
    enumerates rows across every tenant.
    """
    tenant_id = await _seed_tenant(session, "super-admin-tenant")
    entry = await _enqueue_default(session, tenant_id=tenant_id, event_id="evt-sa")
    await session.commit()

    fetched = await get_by_id(session, entry_id=entry.id, tenant_id=None)
    assert fetched is not None
    assert fetched.id == entry.id
    assert fetched.tenant_id == tenant_id


async def test_get_by_id_with_wrong_tenant_returns_none(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """Cross-tenant probe via ``get_by_id`` collapses to a clean miss.

    The DAO maps "row exists but belongs to another tenant" to ``None``
    (NOT a separate "forbidden" sentinel) so admins scoped to tenant A
    cannot enumerate tenant-B ids by observing 404 vs 403 responses.
    """
    tenant_a = await _seed_tenant(session, "probe-tenant-a")
    tenant_b = await _seed_tenant(session, "probe-tenant-b")
    entry = await _enqueue_default(
        session, tenant_id=tenant_a, event_id="evt-probe"
    )
    await session.commit()

    fetched = await get_by_id(session, entry_id=entry.id, tenant_id=tenant_b)
    assert fetched is None, (
        "cross-tenant get_by_id must return None — leaking via "
        "distinct error/return shapes is an existence side channel"
    )


async def test_get_by_event_returns_row_for_matching_triple(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """``get_by_event`` looks up by the idempotency tuple.

    The unique-constraint recovery path inside ``enqueue`` depends on this
    helper returning the exact row that just collided.
    """
    tenant_id = await _seed_tenant(session, "by-event-tenant")
    entry = await _enqueue_default(
        session,
        tenant_id=tenant_id,
        adapter_name="linear",
        event_id="evt-by-event",
    )
    await session.commit()

    fetched = await get_by_event(
        session,
        tenant_id=tenant_id,
        adapter_name="linear",
        event_id="evt-by-event",
    )
    assert fetched is not None
    assert fetched.id == entry.id

    miss = await get_by_event(
        session,
        tenant_id=tenant_id,
        adapter_name="linear",
        event_id="evt-does-not-exist",
    )
    assert miss is None


# ===========================================================================
# Bucket 4 — list_for_tenant / list_due_for_replay /
#           list_abandoned_candidates (4 cases).
# ===========================================================================


async def test_list_for_tenant_paginates_and_returns_total(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """10 rows + ``limit=3, offset=3`` -> 3 rows + ``total=10``."""
    tenant_id = await _seed_tenant(session, "page-tenant")
    for i in range(10):
        await _enqueue_default(
            session, tenant_id=tenant_id, event_id=f"evt-page-{i:02d}"
        )
        await session.commit()

    rows, total = await list_for_tenant(
        session, tenant_id=tenant_id, limit=3, offset=3
    )
    assert total == 10, f"total must report the full filter cardinality, got {total}"
    assert len(rows) == 3, f"limit=3 must cap the page at 3 rows, got {len(rows)}"


async def test_list_for_tenant_status_pending_excludes_terminal_rows(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """``status="pending"`` filter excludes both terminal columns."""
    tenant_id = await _seed_tenant(session, "status-tenant")
    pending = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-pending"
    )
    replayed_row = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-replayed"
    )
    abandoned_row = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-abandoned"
    )
    await session.commit()

    await mark_replayed(session, entry_id=replayed_row.id, tenant_id=tenant_id)
    await mark_abandoned(
        session,
        entry_id=abandoned_row.id,
        tenant_id=tenant_id,
        reason="operator",
    )
    await session.commit()

    rows, total = await list_for_tenant(
        session, tenant_id=tenant_id, status="pending"
    )
    assert total == 1, (
        f"pending filter must report exactly one row, got total={total}"
    )
    assert [r.id for r in rows] == [pending.id]


async def test_list_due_for_replay_returns_only_due_rows_in_fifo_order(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """Acceptance criterion (d) — ``next_retry_at <= now`` AND not terminal,
    ordered by ``created_at ASC`` (FIFO).
    """
    tenant_id = await _seed_tenant(session, "due-tenant")

    older_due = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-due-older"
    )
    await session.commit()
    newer_due = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-due-newer"
    )
    await session.commit()
    not_due = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-not-due"
    )
    await session.commit()

    cutoff_anchor = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)
    await _force_created_at(
        session, entry_id=older_due.id, when=cutoff_anchor - timedelta(hours=2)
    )
    await _force_created_at(
        session, entry_id=newer_due.id, when=cutoff_anchor - timedelta(hours=1)
    )
    await _force_created_at(
        session, entry_id=not_due.id, when=cutoff_anchor
    )

    await session.execute(
        text(
            "UPDATE webhook_dlq_entries "
            "SET next_retry_at = :ts WHERE id IN (:older, :newer)"
        ),
        {
            "ts": _naive(cutoff_anchor - timedelta(minutes=10)),
            "older": older_due.id,
            "newer": newer_due.id,
        },
    )
    await session.execute(
        text(
            "UPDATE webhook_dlq_entries "
            "SET next_retry_at = :ts WHERE id = :id"
        ),
        {"ts": _naive(cutoff_anchor + timedelta(hours=1)), "id": not_due.id},
    )
    await session.commit()

    rows = await list_due_for_replay(session, now=cutoff_anchor)
    ids = [r.id for r in rows]

    assert not_due.id not in ids, (
        "row whose next_retry_at is in the future must NOT be returned"
    )
    assert ids == [older_due.id, newer_due.id], (
        f"due rows must be returned in FIFO created_at ASC order, got {ids}"
    )


async def test_list_abandoned_candidates_respects_fourteen_day_cutoff(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """Acceptance criterion (e) — ``created_at <= now - 14d`` AND not terminal."""
    tenant_id = await _seed_tenant(session, "abandon-tenant")

    aged = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-aged"
    )
    await session.commit()
    fresh = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-fresh"
    )
    await session.commit()

    moment = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)
    cutoff = moment - timedelta(days=DLQ_MAX_AGE_DAYS)
    await _force_created_at(
        session, entry_id=aged.id, when=cutoff - timedelta(seconds=1)
    )
    await _force_created_at(
        session, entry_id=fresh.id, when=cutoff + timedelta(seconds=1)
    )

    rows = await list_abandoned_candidates(session, now=moment)
    ids = [r.id for r in rows]

    assert ids == [aged.id], (
        f"only the aged row should be a candidate; "
        f"got {ids} for cutoff={cutoff.isoformat()}"
    )


# ===========================================================================
# Bucket 5 — mark_replayed / mark_abandoned / increment_attempt (6 cases).
# ===========================================================================


async def test_mark_replayed_sets_replayed_at_and_makes_row_terminal(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """Acceptance criterion (f) happy path — single mutation seal."""
    tenant_id = await _seed_tenant(session, "replay-happy-tenant")
    entry = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-replay"
    )
    await session.commit()

    updated = await mark_replayed(
        session, entry_id=entry.id, tenant_id=tenant_id
    )
    await session.commit()

    assert updated.replayed_at == freeze_now
    assert updated.abandoned_at is None
    assert updated.id == entry.id


async def test_mark_replayed_second_call_raises_already_terminal(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """Acceptance criterion (f) idempotency seal — second mutate is rejected."""
    tenant_id = await _seed_tenant(session, "replay-twice-tenant")
    entry = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-replay-twice"
    )
    await session.commit()

    await mark_replayed(session, entry_id=entry.id, tenant_id=tenant_id)
    await session.commit()

    with pytest.raises(AlreadyTerminalError, match="already terminal"):
        await mark_replayed(session, entry_id=entry.id, tenant_id=tenant_id)


async def test_mark_abandoned_happy_path_records_reason(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """``reason="operator"`` is one of the closed-taxonomy reasons.

    Verifies both ``abandoned_at`` and ``abandoned_reason`` land in the row,
    plus that the row stays terminal afterwards.
    """
    tenant_id = await _seed_tenant(session, "abandon-happy-tenant")
    entry = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-abandon"
    )
    await session.commit()

    updated = await mark_abandoned(
        session, entry_id=entry.id, tenant_id=tenant_id, reason="operator"
    )
    await session.commit()

    assert updated.abandoned_at == freeze_now
    assert updated.abandoned_reason == "operator"
    assert updated.replayed_at is None


async def test_mark_abandoned_with_invalid_reason_raises_value_error(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """Closed-taxonomy enforcement — anything outside the whitelist raises.

    The whitelist is ``{operator, max_age, manual_abandon}``; "garbage"
    must fail before any DB I/O so the ``abandoned_reason`` column can be
    trusted by downstream analytics.
    """
    tenant_id = await _seed_tenant(session, "abandon-bad-tenant")
    entry = await _enqueue_default(
        session, tenant_id=tenant_id, event_id="evt-bad-reason"
    )
    await session.commit()

    with pytest.raises(ValueError, match="invalid abandoned_reason"):
        await mark_abandoned(
            session, entry_id=entry.id, tenant_id=tenant_id, reason="garbage"
        )

    refetched = await get_by_id(session, entry_id=entry.id, tenant_id=tenant_id)
    assert refetched is not None
    assert refetched.abandoned_at is None, (
        "ValueError must short-circuit BEFORE the row is mutated"
    )
    assert refetched.abandoned_reason is None


async def test_mark_replayed_cross_tenant_probe_raises_not_found(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """Acceptance criterion (f) — cross-tenant mutation collapses to 404.

    Admin scoped to tenant B targeting a row owned by tenant A must NOT
    see a distinct "forbidden" — that would leak existence. The DAO
    raises :exc:`DlqEntryNotFoundError` (the same exception a true miss
    raises) so the side channel stays closed.
    """
    tenant_a = await _seed_tenant(session, "cross-tenant-a")
    tenant_b = await _seed_tenant(session, "cross-tenant-b")
    entry = await _enqueue_default(
        session, tenant_id=tenant_a, event_id="evt-cross"
    )
    await session.commit()

    with pytest.raises(DlqEntryNotFoundError, match="not found"):
        await mark_replayed(session, entry_id=entry.id, tenant_id=tenant_b)

    untouched = await get_by_id(
        session, entry_id=entry.id, tenant_id=tenant_a
    )
    assert untouched is not None
    assert untouched.replayed_at is None, (
        "tenant B's failed probe must NOT mutate tenant A's row"
    )


async def test_increment_attempt_bumps_count_and_recomputes_backoff(
    session: AsyncSession, freeze_now: datetime
) -> None:
    """attempt_count++; ``next_retry_at`` reflows; error fields overwritten."""
    tenant_id = await _seed_tenant(session, "inc-tenant")
    entry = await _enqueue_default(
        session,
        tenant_id=tenant_id,
        event_id="evt-inc",
        last_error_code="http_5xx",
        last_status_code=503,
        attempt_count=0,
    )
    await session.commit()
    initial_count = entry.attempt_count

    updated = await increment_attempt(
        session,
        entry_id=entry.id,
        last_error_code="circuit_open",
        last_status_code=None,
    )
    await session.commit()

    expected_next = _FIXED_NOW + timedelta(
        seconds=DLQ_BACKOFF_BASE_SECONDS * DLQ_BACKOFF_FACTOR
    )
    assert updated.attempt_count == initial_count + 1
    assert updated.last_error_code == "circuit_open"
    assert updated.last_status_code is None
    assert updated.next_retry_at == expected_next
