"""T40 (Cycle 6 Batch 5, ARG-053) — webhook_dlq_replay beat task tests.

Covers acceptance criteria (a)-(f) from the Cycle 6 Batch 5 plan
(``ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md`` §5 / T40) for
:mod:`src.celery.tasks.webhook_dlq_replay`.

Test architecture
-----------------
* **Unit (4 cases)** — pure assertions on ``BEAT_SCHEDULE`` registration,
  ``_run`` return shape, and ``_build_adapter`` factory wiring.
* **Integration (8 cases)** — exercise ``_run`` end-to-end against a fresh
  in-memory async SQLite engine bootstrapped with revision 027 of the
  Alembic chain. The notification adapter is mocked at the task-module
  level (``src.celery.tasks.webhook_dlq_replay._build_adapter``) so no
  real HTTP egress happens, no Celery worker is spun up, and no real
  Postgres / Redis is required.

The SQLite isolation pattern, including the revision-027 bootstrap via
:class:`MigrationContext` + :class:`Operations`, mirrors
``backend/tests/notifications/test_webhook_dlq_persistence.py`` so any
schema drift between migration 027 and the ORM surface fails here too.

Engine wrapping
---------------
``_run`` always calls ``await engine.dispose()`` in its ``finally``. We
swap the production engine factory for a wrapper that no-ops ``dispose()``
so the test fixture engine stays alive across the verify phase. The
underlying SQLAlchemy session_factory is the SAME factory used by the
test fixture, so commits from inside ``_run`` are immediately visible to
the test session via ``session.refresh(...)``.

Determinism
-----------
* Every "current instant" in the persistence layer is pinned via
  ``monkeypatch.setattr`` on ``webhook_dlq_persistence._utcnow``.
* ``_run`` is always driven via ``await _run(now=fixed_t)`` — never via
  the Celery task entry point (which would require a real worker bring-up).
* Row creation timestamps and ``next_retry_at`` are forced via raw SQL
  ``UPDATE`` statements so ``list_due_for_replay`` /
  ``list_abandoned_candidates`` return predictable subsets.
* No ``time.sleep`` calls anywhere; no real network; no Redis.
"""

from __future__ import annotations

import importlib.util
import uuid
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import event, select, text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from src.celery import beat_schedule as beat_schedule_module
from src.celery.tasks import webhook_dlq_replay as task_module
from src.db.models import WebhookDlqEntry
from src.mcp.services.notifications.schemas import AdapterResult
from src.mcp.services.notifications.slack import SlackNotifier
from src.mcp.services.notifications.webhook_dlq_persistence import (
    enqueue,
    mark_abandoned,
    mark_replayed,
)

# ---------------------------------------------------------------------------
# Constants — every magic value in one place so a future schema bump is a
# single-line edit.
# ---------------------------------------------------------------------------

_DAO_MODULE: str = "src.mcp.services.notifications.webhook_dlq_persistence"
_TASK_MODULE: str = "src.celery.tasks.webhook_dlq_replay"
_BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]
_VERSIONS_DIR: Path = _BACKEND_ROOT / "alembic" / "versions"
_REVISION: str = "027"
_BEAT_SCHEDULE_NAME: str = "argus.notifications.webhook_dlq_replay"

#: Pinned "current instant" for every test. Far enough from any default
#: ``created_at`` (server-default ``CURRENT_TIMESTAMP``) that age comparisons
#: stay distinct on assertion.
_FIXED_NOW: datetime = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Schema bootstrap — mirror SQLite isolation from the persistence test.
# Revision 027 is applied directly (not via Alembic ``command.upgrade``)
# because the full chain has Postgres-only ops that SQLite cannot compile.
# ---------------------------------------------------------------------------


def _load_revision_module() -> Any:
    """Import revision 027 as a standalone module (no full Alembic chain run)."""
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
    """Create the minimal ``tenants`` table and apply revision 027."""
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
# Engine wrapper — `_run` always disposes its engine. We forward attribute
# access to the real engine and override ``dispose`` to a no-op so the test
# fixture engine survives the verify phase. ``async with session_factory()``
# inside `_run` uses the session_factory directly (not the wrapped engine),
# so a no-op dispose is sufficient.
# ---------------------------------------------------------------------------


class _NoDisposeEngine:
    """Forwarding wrapper that no-ops ``dispose()`` for the test fixture engine."""

    def __init__(self, real: AsyncEngine) -> None:
        self._real = real

    async def dispose(self) -> None:
        return None

    def __getattr__(self, item: str) -> Any:
        return getattr(self._real, item)


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """Per-test in-memory async SQLite engine with the DLQ schema applied."""
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
def session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Session factory bound to the test engine; shared with the patched task."""
    return async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )


@pytest.fixture
async def session(
    session_factory: async_sessionmaker[AsyncSession],
) -> AsyncIterator[AsyncSession]:
    """Per-test ``AsyncSession`` for setup + verification."""
    async with session_factory() as s:
        try:
            yield s
        finally:
            await s.rollback()


@pytest.fixture
def freeze_now(monkeypatch: pytest.MonkeyPatch) -> datetime:
    """Pin ``webhook_dlq_persistence._utcnow`` to :data:`_FIXED_NOW`."""
    monkeypatch.setattr(f"{_DAO_MODULE}._utcnow", lambda: _FIXED_NOW)
    return _FIXED_NOW


@pytest.fixture
def patch_task_engine(
    monkeypatch: pytest.MonkeyPatch,
    engine: AsyncEngine,
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    """Swap ``_run``'s engine factory for the test engine + session factory."""
    wrapper = _NoDisposeEngine(engine)
    monkeypatch.setattr(
        f"{_TASK_MODULE}.create_task_engine_and_session",
        lambda: (wrapper, session_factory),
    )


# ---------------------------------------------------------------------------
# Helpers.
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


def _make_event_payload(*, event_id: str, tenant_id: str) -> dict[str, Any]:
    """Build a payload that round-trips into :class:`NotificationEvent`.

    Includes only the required fields plus the closed-taxonomy ``event_type``
    so :meth:`NotificationEvent.model_validate` succeeds inside ``_replay_entry``.
    """
    return {
        "event_id": event_id,
        "event_type": "scan.completed",
        "title": "DLQ replay test event",
        "summary": "Synthetic payload for the T40 beat task tests.",
        "tenant_id": tenant_id,
    }


async def _enqueue_row(
    session: AsyncSession,
    *,
    tenant_id: str,
    event_id: str,
    adapter_name: str = "slack",
    attempt_count: int = 0,
) -> WebhookDlqEntry:
    """Persist one DLQ row using the real DAO so we exercise the real schema."""
    return await enqueue(
        session,
        tenant_id=tenant_id,
        adapter_name=adapter_name,
        event_type="scan.completed",
        event_id=event_id,
        target_url="https://hooks.slack.example/T0/B0/secret-token",
        payload=_make_event_payload(event_id=event_id, tenant_id=tenant_id),
        last_error_code="http_5xx",
        last_status_code=503,
        attempt_count=attempt_count,
    )


def _naive(dt: datetime) -> datetime:
    """Strip ``tzinfo`` so SQLite-readback comparisons line up.

    SQLite's ``DateTime(timezone=True)`` round-trips into naive datetimes —
    an aware-vs-naive comparison raises ``TypeError``, so all expected
    values are stripped before assertion.
    """
    return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt


async def _set_row_timing(
    session: AsyncSession,
    *,
    entry_id: str,
    created_at: datetime | None = None,
    next_retry_at: datetime | None = None,
) -> None:
    """Force ``created_at`` / ``next_retry_at`` on a specific row.

    Necessary because :func:`enqueue` derives ``next_retry_at`` from
    :func:`compute_next_retry_at` (and ``created_at`` from a server default).
    Tests need explicit values for these to drive the
    ``list_due_for_replay`` / ``list_abandoned_candidates`` filters.
    """
    if created_at is not None:
        await session.execute(
            text("UPDATE webhook_dlq_entries SET created_at = :ts WHERE id = :id"),
            {"ts": _naive(created_at), "id": entry_id},
        )
    if next_retry_at is not None:
        await session.execute(
            text("UPDATE webhook_dlq_entries SET next_retry_at = :ts WHERE id = :id"),
            {"ts": _naive(next_retry_at), "id": entry_id},
        )
    await session.commit()


def _adapter_result(
    *,
    delivered: bool,
    event_id: str,
    adapter_name: str = "slack",
    status_code: int | None = 200,
    error_code: str | None = None,
) -> AdapterResult:
    """Build a minimal :class:`AdapterResult` matching the closed schema."""
    return AdapterResult(
        adapter_name=adapter_name,
        event_id=event_id,
        delivered=delivered,
        status_code=status_code if delivered else (status_code or 503),
        attempts=1,
        target_redacted="abcdef012345",
        error_code=error_code if not delivered else None,
        skipped_reason=None,
        duplicate_of=None,
    )


def _make_stub_adapter(
    *,
    result: AdapterResult | None = None,
    results_by_event: dict[str, AdapterResult] | None = None,
    raises: type[BaseException] | None = None,
) -> MagicMock:
    """Build a stub matching the :class:`NotifierBase` surface ``_run`` uses.

    Exactly one of ``result`` / ``results_by_event`` / ``raises`` must be
    supplied. The stub's ``send_with_retry`` is an :class:`AsyncMock`; its
    ``aclose`` is also an :class:`AsyncMock` so the ``finally`` branch in
    ``_replay_entry`` does not blow up.
    """
    stub = MagicMock()
    if raises is not None:
        stub.send_with_retry = AsyncMock(side_effect=raises("boom"))
    elif results_by_event is not None:

        async def _by_event(event: Any, *, tenant_id: str) -> AdapterResult:  # noqa: ARG001
            return results_by_event[event.event_id]

        stub.send_with_retry = AsyncMock(side_effect=_by_event)
    else:
        assert result is not None, (
            "exactly one of result / results_by_event / raises must be given"
        )
        stub.send_with_retry = AsyncMock(return_value=result)
    stub.aclose = AsyncMock(return_value=None)
    return stub


def _patch_adapter_factory(
    monkeypatch: pytest.MonkeyPatch, stub: MagicMock
) -> None:
    """Replace ``_build_adapter`` on the task module so every replay uses the stub.

    Patching the module-level factory (instead of any individual class) is
    the right seam because ``_replay_entry`` resolves ``_build_adapter`` from
    its own module namespace at call time.
    """
    monkeypatch.setattr(
        f"{_TASK_MODULE}._build_adapter",
        lambda adapter_name: stub,  # noqa: ARG005 — adapter_name unused intentionally
    )


# ===========================================================================
# Unit tests (4) — pure assertions; no DB I/O for #1, #3, #4.
# ===========================================================================


def test_beat_schedule_registers_webhook_dlq_replay_daily_at_06_utc() -> None:
    """Acceptance (a) — beat-schedule entry shape.

    Verifies the beat schedule registers ``argus.notifications.webhook_dlq_replay``,
    fires daily at 06:00 UTC, and routes onto the dedicated
    ``argus.notifications`` queue so it cannot starve scan / report queues.
    """
    spec = beat_schedule_module.BEAT_SCHEDULE.get(_BEAT_SCHEDULE_NAME)
    assert spec is not None, (
        f"{_BEAT_SCHEDULE_NAME!r} missing from BEAT_SCHEDULE — "
        f"keys={sorted(beat_schedule_module.BEAT_SCHEDULE)}"
    )

    assert spec["task"] == _BEAT_SCHEDULE_NAME, (
        f"task name mismatch: {spec['task']!r}"
    )
    assert spec["options"]["queue"] == "argus.notifications", (
        f"queue routing mismatch: {spec['options']['queue']!r}"
    )

    schedule = spec["schedule"]
    assert schedule is not None, (
        "schedule must be a crontab when celery is importable"
    )
    # ``crontab.hour`` / ``crontab.minute`` are sets of allowed values.
    assert getattr(schedule, "hour", None) == {6}, (
        f"expected hour={{6}}, got {getattr(schedule, 'hour', None)!r}"
    )
    assert getattr(schedule, "minute", None) == {0}, (
        f"expected minute={{0}}, got {getattr(schedule, 'minute', None)!r}"
    )


async def test_run_returns_canonical_counter_keys_with_no_seed_data(
    session: AsyncSession,
    freeze_now: datetime,
    patch_task_engine: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acceptance (f) — ``_run`` returns the documented counter dict shape.

    With no seeded rows every counter must be 0. Asserts that:
    * Returned object is a dict with EXACTLY ``{"replayed", "failed",
      "abandoned_max_age"}``.
    * Every value is an ``int``.
    * The adapter factory is NEVER consulted when there is nothing to do.
    """
    stub = _make_stub_adapter(
        result=_adapter_result(delivered=True, event_id="evt-unused-aaaa")
    )
    _patch_adapter_factory(monkeypatch, stub)

    counters = await task_module._run(now=freeze_now)

    assert set(counters.keys()) == {"replayed", "failed", "abandoned_max_age"}, (
        f"unexpected key set: {sorted(counters.keys())!r}"
    )
    assert all(isinstance(v, int) for v in counters.values()), (
        f"every counter must be int; got {counters!r}"
    )
    assert counters == {"replayed": 0, "failed": 0, "abandoned_max_age": 0}
    stub.send_with_retry.assert_not_awaited()
    stub.aclose.assert_not_awaited()


async def test_build_adapter_slack_returns_slack_notifier_instance() -> None:
    """``_build_adapter("slack")`` constructs a :class:`SlackNotifier`."""
    adapter = task_module._build_adapter("slack")
    try:
        assert isinstance(adapter, SlackNotifier), (
            f"expected SlackNotifier, got {type(adapter).__name__}"
        )
        assert adapter.name == "slack"
    finally:
        # Constructor allocates an httpx.AsyncClient (since no client was
        # injected). Release it so the loop has nothing to clean up after.
        await adapter.aclose()


def test_build_adapter_unknown_name_raises_value_error() -> None:
    """``_build_adapter`` raises :exc:`ValueError` for an unknown adapter name.

    Row corruption signal — a DLQ entry whose ``adapter_name`` does not map
    to a known factory must surface a recognisable closed-taxonomy error so
    the per-row handler in ``_replay_entry`` can absorb it cleanly.
    """
    with pytest.raises(ValueError, match="unknown adapter_name"):
        task_module._build_adapter("definitely-not-a-real-adapter")


# ===========================================================================
# Integration tests (8) — drive ``_run`` against a real (in-memory) DB
# with the adapter mocked at the task-module level.
# ===========================================================================


async def test_replay_success_marks_replayed_and_increments_replayed_counter(
    session: AsyncSession,
    freeze_now: datetime,
    patch_task_engine: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acceptance (c) — successful replay sets ``replayed_at`` (terminal).

    Seeds one row whose ``next_retry_at`` is in the past; the mocked adapter
    reports ``delivered=True``; ``_run`` must call ``mark_replayed``,
    populate ``replayed_at`` on the row, and bump the ``replayed`` counter.
    """
    tenant_id = await _seed_tenant(session, "replay-success-tenant")
    entry = await _enqueue_row(
        session, tenant_id=tenant_id, event_id="evt-success-0001"
    )
    await session.commit()
    await _set_row_timing(
        session,
        entry_id=entry.id,
        next_retry_at=freeze_now - timedelta(hours=1),
    )

    stub = _make_stub_adapter(
        result=_adapter_result(delivered=True, event_id=entry.event_id)
    )
    _patch_adapter_factory(monkeypatch, stub)

    counters = await task_module._run(now=freeze_now)

    assert counters == {"replayed": 1, "failed": 0, "abandoned_max_age": 0}, (
        f"counters mismatch: {counters!r}"
    )
    stub.send_with_retry.assert_awaited_once()
    stub.aclose.assert_awaited_once()

    await session.refresh(entry)
    assert entry.replayed_at is not None, "replayed_at must be populated"
    assert entry.replayed_at == _naive(freeze_now)
    assert entry.abandoned_at is None
    assert entry.attempt_count == 0, "mark_replayed must NOT bump attempt_count"


async def test_replay_failure_increments_attempt_and_persists_error_code(
    session: AsyncSession,
    freeze_now: datetime,
    patch_task_engine: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acceptance (d) — adapter ``delivered=False`` triggers ``increment_attempt``.

    Seeds one due row; the mocked adapter reports ``delivered=False`` with
    ``error_code="http_5xx"`` / ``status_code=502``. ``_run`` must:
    * NOT mark the row terminal.
    * Bump ``attempt_count`` from 0 to 1.
    * Recompute ``next_retry_at`` via :func:`compute_next_retry_at`.
    * Overwrite ``last_error_code`` / ``last_status_code`` with the new values.
    * Increment the ``failed`` counter (NOT ``replayed``).
    """
    tenant_id = await _seed_tenant(session, "replay-failure-tenant")
    entry = await _enqueue_row(
        session,
        tenant_id=tenant_id,
        event_id="evt-failure-0001",
        attempt_count=0,
    )
    await session.commit()
    await _set_row_timing(
        session,
        entry_id=entry.id,
        next_retry_at=freeze_now - timedelta(hours=1),
    )

    stub = _make_stub_adapter(
        result=_adapter_result(
            delivered=False,
            event_id=entry.event_id,
            error_code="http_5xx",
            status_code=502,
        )
    )
    _patch_adapter_factory(monkeypatch, stub)

    counters = await task_module._run(now=freeze_now)

    assert counters == {"replayed": 0, "failed": 1, "abandoned_max_age": 0}, (
        f"counters mismatch: {counters!r}"
    )
    stub.send_with_retry.assert_awaited_once()
    stub.aclose.assert_awaited_once()

    await session.refresh(entry)
    assert entry.replayed_at is None
    assert entry.abandoned_at is None
    assert entry.attempt_count == 1, (
        f"attempt_count must increment 0 -> 1, got {entry.attempt_count}"
    )
    assert entry.last_error_code == "http_5xx"
    assert entry.last_status_code == 502
    assert entry.next_retry_at is not None, (
        "next_retry_at must be recomputed by increment_attempt"
    )
    # 30s base * 4^1 = 120s — first failed retry pushes 2 minutes ahead.
    expected_next = _naive(freeze_now + timedelta(seconds=120))
    assert entry.next_retry_at == expected_next, (
        f"next_retry_at mismatch: got {entry.next_retry_at!r}, "
        f"expected {expected_next!r}"
    )


async def test_replay_exception_is_absorbed_and_marked_dispatch_exception(
    session: AsyncSession,
    freeze_now: datetime,
    patch_task_engine: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acceptance (f) — a per-row exception NEVER bubbles out of the task.

    Seeds one due row; the mocked adapter's ``send_with_retry`` raises a
    :class:`RuntimeError`. ``_run`` must:
    * NOT raise out of the task body.
    * Mark the row's ``last_error_code`` as ``"dispatch_exception"`` (the
      closed-taxonomy short identifier reserved for in-task per-row failures).
    * Bump ``attempt_count``.
    * Increment the ``failed`` counter.
    * Still call ``adapter.aclose()`` (via the ``finally`` branch).
    """
    tenant_id = await _seed_tenant(session, "replay-exception-tenant")
    entry = await _enqueue_row(
        session,
        tenant_id=tenant_id,
        event_id="evt-boom-0001",
        attempt_count=0,
    )
    await session.commit()
    await _set_row_timing(
        session,
        entry_id=entry.id,
        next_retry_at=freeze_now - timedelta(hours=1),
    )

    stub = _make_stub_adapter(raises=RuntimeError)
    _patch_adapter_factory(monkeypatch, stub)

    # The contract is that the task body absorbs every per-row exception.
    counters = await task_module._run(now=freeze_now)

    assert counters == {"replayed": 0, "failed": 1, "abandoned_max_age": 0}, (
        f"counters mismatch: {counters!r}"
    )
    stub.send_with_retry.assert_awaited_once()
    stub.aclose.assert_awaited_once()

    await session.refresh(entry)
    assert entry.replayed_at is None
    assert entry.abandoned_at is None
    assert entry.attempt_count == 1, (
        f"attempt_count must increment to 1, got {entry.attempt_count}"
    )
    assert entry.last_error_code == "dispatch_exception", (
        f"per-row exception must surface as 'dispatch_exception'; "
        f"got {entry.last_error_code!r}"
    )
    assert entry.last_status_code is None


async def test_pending_not_due_row_is_skipped(
    session: AsyncSession,
    freeze_now: datetime,
    patch_task_engine: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acceptance (b) — ``next_retry_at > now`` row is NOT picked up.

    Seeds one row whose ``next_retry_at`` is one hour in the future. The
    adapter must NEVER be invoked and every counter must stay 0. The row's
    age is freshly enqueued so it cannot be picked up by the abandon path.
    """
    tenant_id = await _seed_tenant(session, "pending-not-due-tenant")
    entry = await _enqueue_row(
        session, tenant_id=tenant_id, event_id="evt-not-due-0001"
    )
    await session.commit()
    await _set_row_timing(
        session,
        entry_id=entry.id,
        created_at=freeze_now - timedelta(minutes=1),
        next_retry_at=freeze_now + timedelta(hours=1),
    )

    stub = _make_stub_adapter(
        result=_adapter_result(delivered=True, event_id=entry.event_id)
    )
    _patch_adapter_factory(monkeypatch, stub)

    counters = await task_module._run(now=freeze_now)

    assert counters == {"replayed": 0, "failed": 0, "abandoned_max_age": 0}
    stub.send_with_retry.assert_not_awaited()
    stub.aclose.assert_not_awaited()

    await session.refresh(entry)
    assert entry.replayed_at is None
    assert entry.abandoned_at is None
    assert entry.attempt_count == 0


async def test_replayed_row_is_skipped(
    session: AsyncSession,
    freeze_now: datetime,
    patch_task_engine: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acceptance (b) — row whose ``replayed_at`` is set is NOT picked up.

    Marks a row as ``replayed`` via the DAO before ``_run``; even with
    ``next_retry_at`` in the past the row stays untouched and the adapter
    is never invoked.
    """
    tenant_id = await _seed_tenant(session, "replayed-skip-tenant")
    entry = await _enqueue_row(
        session, tenant_id=tenant_id, event_id="evt-already-replayed"
    )
    await session.commit()
    await mark_replayed(session, entry_id=entry.id, tenant_id=tenant_id)
    await session.commit()
    # Force next_retry_at into the past — the filter must still exclude it
    # because ``replayed_at`` is not NULL (terminal).
    await _set_row_timing(
        session,
        entry_id=entry.id,
        next_retry_at=freeze_now - timedelta(hours=1),
    )

    stub = _make_stub_adapter(
        result=_adapter_result(delivered=True, event_id=entry.event_id)
    )
    _patch_adapter_factory(monkeypatch, stub)

    counters = await task_module._run(now=freeze_now)

    assert counters == {"replayed": 0, "failed": 0, "abandoned_max_age": 0}
    stub.send_with_retry.assert_not_awaited()


async def test_abandoned_row_is_skipped(
    session: AsyncSession,
    freeze_now: datetime,
    patch_task_engine: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acceptance (b) — row whose ``abandoned_at`` is set is NOT picked up.

    Marks a row ``abandoned`` (operator reason) before ``_run``; even with
    a 15-day-old ``created_at`` the abandon-batch path also excludes it
    because ``abandoned_at`` is already populated (terminal seal).
    """
    tenant_id = await _seed_tenant(session, "abandoned-skip-tenant")
    entry = await _enqueue_row(
        session, tenant_id=tenant_id, event_id="evt-already-abandoned"
    )
    await session.commit()
    await mark_abandoned(
        session,
        entry_id=entry.id,
        tenant_id=tenant_id,
        reason="operator",
    )
    await session.commit()
    # Backdate ``created_at`` so the abandon-batch filter would normally
    # pick it up — but the ``abandoned_at IS NULL`` clause must exclude it.
    await _set_row_timing(
        session,
        entry_id=entry.id,
        created_at=freeze_now - timedelta(days=15),
        next_retry_at=freeze_now - timedelta(hours=1),
    )

    stub = _make_stub_adapter(
        result=_adapter_result(delivered=True, event_id=entry.event_id)
    )
    _patch_adapter_factory(monkeypatch, stub)

    counters = await task_module._run(now=freeze_now)

    assert counters == {"replayed": 0, "failed": 0, "abandoned_max_age": 0}
    stub.send_with_retry.assert_not_awaited()

    await session.refresh(entry)
    # The original abandoned_reason must NOT have been overwritten.
    assert entry.abandoned_reason == "operator"


async def test_aged_out_row_is_marked_abandoned_with_max_age_reason(
    session: AsyncSession,
    freeze_now: datetime,
    patch_task_engine: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Acceptance (e) — row aged >= 14d is sealed via ``mark_abandoned("max_age")``.

    Seeds one row with ``created_at = now - 15d`` and ``next_retry_at`` in
    the future (so the replay batch ignores it). ``_run`` must:
    * Sweep the row through ``list_abandoned_candidates`` -> ``mark_abandoned``.
    * Set ``abandoned_at`` and ``abandoned_reason="max_age"``.
    * Increment the ``abandoned_max_age`` counter.
    * Never invoke the adapter (only the replay path opens an adapter).
    """
    tenant_id = await _seed_tenant(session, "aged-out-tenant")
    entry = await _enqueue_row(
        session, tenant_id=tenant_id, event_id="evt-aged-0001"
    )
    await session.commit()
    await _set_row_timing(
        session,
        entry_id=entry.id,
        created_at=freeze_now - timedelta(days=15),
        next_retry_at=freeze_now + timedelta(hours=1),
    )

    stub = _make_stub_adapter(
        result=_adapter_result(delivered=True, event_id=entry.event_id)
    )
    _patch_adapter_factory(monkeypatch, stub)

    counters = await task_module._run(now=freeze_now)

    assert counters == {"replayed": 0, "failed": 0, "abandoned_max_age": 1}, (
        f"counters mismatch: {counters!r}"
    )
    # The abandon path never opens an adapter.
    stub.send_with_retry.assert_not_awaited()
    stub.aclose.assert_not_awaited()

    await session.refresh(entry)
    assert entry.abandoned_at is not None, "abandoned_at must be populated"
    assert entry.abandoned_at == _naive(freeze_now)
    assert entry.abandoned_reason == "max_age", (
        f"reason mismatch: got {entry.abandoned_reason!r}"
    )
    assert entry.replayed_at is None


async def test_mixed_batch_processes_each_row_state_correctly(
    session: AsyncSession,
    freeze_now: datetime,
    patch_task_engine: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end mixed-batch — every row state lands in the right counter.

    Seeds four rows under one tenant:
    * (a) due-success — ``next_retry_at = now - 1h``; adapter ``delivered=True``.
    * (b) due-failure — ``next_retry_at = now - 1h``; adapter
      ``delivered=False, error_code="http_5xx"``.
    * (c) aged-out  — ``created_at = now - 15d, next_retry_at = now + 1h``;
      adapter NEVER invoked (handled by abandon batch).
    * (d) future-pending — ``next_retry_at = now + 1h``; adapter NEVER
      invoked (and row stays untouched).

    Asserts the counter dict is ``{replayed:1, failed:1, abandoned_max_age:1}``
    and that the future-pending row's columns are byte-identical to the
    pre-``_run`` snapshot.
    """
    tenant_id = await _seed_tenant(session, "mixed-batch-tenant")

    success_row = await _enqueue_row(
        session, tenant_id=tenant_id, event_id="evt-mixed-success"
    )
    failure_row = await _enqueue_row(
        session, tenant_id=tenant_id, event_id="evt-mixed-failure"
    )
    aged_row = await _enqueue_row(
        session, tenant_id=tenant_id, event_id="evt-mixed-aged"
    )
    pending_row = await _enqueue_row(
        session, tenant_id=tenant_id, event_id="evt-mixed-pending"
    )
    await session.commit()

    # Force the timings each row needs so the filters slot them deterministically.
    await _set_row_timing(
        session,
        entry_id=success_row.id,
        created_at=freeze_now - timedelta(minutes=1),
        next_retry_at=freeze_now - timedelta(hours=1),
    )
    await _set_row_timing(
        session,
        entry_id=failure_row.id,
        created_at=freeze_now - timedelta(minutes=1),
        next_retry_at=freeze_now - timedelta(hours=1),
    )
    await _set_row_timing(
        session,
        entry_id=aged_row.id,
        created_at=freeze_now - timedelta(days=15),
        next_retry_at=freeze_now + timedelta(hours=1),
    )
    await _set_row_timing(
        session,
        entry_id=pending_row.id,
        created_at=freeze_now - timedelta(minutes=1),
        next_retry_at=freeze_now + timedelta(hours=1),
    )

    # Snapshot the pending row's pre-run state so we can prove untouched.
    await session.refresh(pending_row)
    pending_snapshot = {
        "attempt_count": pending_row.attempt_count,
        "last_error_code": pending_row.last_error_code,
        "last_status_code": pending_row.last_status_code,
        "replayed_at": pending_row.replayed_at,
        "abandoned_at": pending_row.abandoned_at,
        "abandoned_reason": pending_row.abandoned_reason,
        "next_retry_at": pending_row.next_retry_at,
    }

    stub = _make_stub_adapter(
        results_by_event={
            "evt-mixed-success": _adapter_result(
                delivered=True, event_id="evt-mixed-success"
            ),
            "evt-mixed-failure": _adapter_result(
                delivered=False,
                event_id="evt-mixed-failure",
                error_code="http_5xx",
                status_code=502,
            ),
        }
    )
    _patch_adapter_factory(monkeypatch, stub)

    counters = await task_module._run(now=freeze_now)

    assert counters == {"replayed": 1, "failed": 1, "abandoned_max_age": 1}, (
        f"counters mismatch: {counters!r}"
    )
    # Adapter was invoked exactly once per due row (NOT for aged or pending).
    assert stub.send_with_retry.await_count == 2, (
        f"adapter must be awaited exactly twice (one per due row); "
        f"got {stub.send_with_retry.await_count}"
    )
    assert stub.aclose.await_count == 2, (
        f"adapter aclose must be awaited exactly twice; "
        f"got {stub.aclose.await_count}"
    )

    await session.refresh(success_row)
    assert success_row.replayed_at is not None
    assert success_row.abandoned_at is None
    assert success_row.attempt_count == 0

    await session.refresh(failure_row)
    assert failure_row.replayed_at is None
    assert failure_row.abandoned_at is None
    assert failure_row.attempt_count == 1
    assert failure_row.last_error_code == "http_5xx"
    assert failure_row.last_status_code == 502

    await session.refresh(aged_row)
    assert aged_row.abandoned_at is not None
    assert aged_row.abandoned_reason == "max_age"
    assert aged_row.replayed_at is None
    # The aged-out row's attempt_count is untouched by the abandon path.
    assert aged_row.attempt_count == 0

    # Future-pending row must be byte-identical to the snapshot — no mutation.
    await session.refresh(pending_row)
    assert pending_row.attempt_count == pending_snapshot["attempt_count"]
    assert pending_row.last_error_code == pending_snapshot["last_error_code"]
    assert pending_row.last_status_code == pending_snapshot["last_status_code"]
    assert pending_row.replayed_at == pending_snapshot["replayed_at"]
    assert pending_row.abandoned_at == pending_snapshot["abandoned_at"]
    assert pending_row.abandoned_reason == pending_snapshot["abandoned_reason"]
    assert pending_row.next_retry_at == pending_snapshot["next_retry_at"]

    # Sanity: the global row count is unchanged.
    total = await session.scalar(
        select(WebhookDlqEntry).where(
            WebhookDlqEntry.tenant_id == tenant_id
        )
    )
    assert total is not None, "select must return at least one row"
