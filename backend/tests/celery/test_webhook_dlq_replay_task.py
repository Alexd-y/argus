"""T40 (Cycle 6 Batch 5, ARG-053) — Celery beat task ``webhook_dlq_replay`` tests.

Covers the T40 acceptance criteria from
``ai_docs/develop/plans/2026-04-22-argus-cycle6-b5.md`` §5:

* Unit (4):
  1. ``BEAT_SCHEDULE`` registration — entry name, schedule (06:00 UTC), and
     queue (``argus.notifications``) plus the ``argus.notifications.*`` route
     wired in ``src.celery_app``.
  2. ``_run`` return shape — exact ``{"replayed", "failed", "abandoned_max_age"}``
     keys, integer values.
  3. ``_build_adapter("slack")`` returns a ``SlackNotifier`` instance.
  4. ``_build_adapter`` rejects an unknown adapter name with ``ValueError``.

* Integration (8) — drive ``await _run(now=fixed_t)`` against an in-memory
  SQLite engine bootstrapped with revision 027 (mirrors the persistence-DAO
  test suite) plus a stubbed adapter:
  1. Replay-success: due row + ``delivered=True`` -> ``replayed_at`` set,
     counter ``replayed=1``.
  2. Replay-failure: due row + ``delivered=False, error_code="http_5xx"`` ->
     ``attempt_count`` bumped, counter ``failed=1``.
  3. Replay-exception: ``send_with_retry`` raises -> task body absorbs the
     exception, ``last_error_code="dispatch_exception"``.
  4. Pending-not-due skip: ``next_retry_at`` in the future -> not picked up.
  5. Replayed-skip: ``replayed_at`` already set -> not picked up.
  6. Abandoned-skip: ``abandoned_at`` already set -> not picked up.
  7. Abandon-aged: row older than ``DLQ_MAX_AGE_DAYS`` -> ``mark_abandoned``
     with ``reason="max_age"``, counter ``abandoned_max_age=1``.
  8. Mixed batch: success + failure + aged + future-pending in one tick.

Architecture
------------
* Each test gets a fresh in-memory async SQLite engine + revision 027 schema
  (mirrors ``tests/notifications/test_webhook_dlq_persistence.py``).
* The task module's ``create_task_engine_and_session`` is monkeypatched to
  return ``(_NoDisposeEngine(), session_factory)`` so ``_run``'s
  ``await engine.dispose()`` is a no-op and the in-memory DB survives long
  enough for post-call assertions on the same engine.
* ``_build_adapter`` is monkeypatched at the task-module level so each test
  injects its own ``AdapterResult`` (or exception) without any HTTP egress.
* ``_utcnow`` in the persistence module is pinned per test so
  ``mark_replayed`` / ``mark_abandoned`` write deterministic timestamps.

Determinism
-----------
* No real network, no real Celery broker, no Celery worker.
* No ``time.sleep``; all "current instants" come from ``_FIXED_NOW`` or the
  ``freeze_dao_now`` fixture.
* ``await _run(now=_FIXED_NOW)`` is invoked directly — never via
  ``webhook_dlq_replay.delay()`` / ``apply_async``.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Layer 1 — safe environment defaults BEFORE any ``src.*`` import.
# Mirrors the ``tests/api/admin/conftest.py`` and ``tests/unit/conftest.py``
# pattern: production ``Settings`` validators reject empty JWT_SECRET, and
# without a sqlite DSN ``settings.database_url`` would point at Postgres
# (per ``backend/.env``) and any lazy connection would fail.
# ---------------------------------------------------------------------------

import os

os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault(
    "JWT_SECRET",
    "test-secret-not-for-prod-but-required-by-settings",
)
os.environ.setdefault("ARGUS_TEST_MODE", "1")


# ---------------------------------------------------------------------------
# Layer 2 — heavy imports (alembic, sqlalchemy, src.*).
# ---------------------------------------------------------------------------

import importlib.util  # noqa: E402
import uuid  # noqa: E402
from collections.abc import AsyncIterator  # noqa: E402
from datetime import UTC, datetime, timedelta  # noqa: E402
from pathlib import Path  # noqa: E402
from typing import Any  # noqa: E402
from unittest.mock import AsyncMock, MagicMock  # noqa: E402

import pytest  # noqa: E402
from alembic.migration import MigrationContext  # noqa: E402
from alembic.operations import Operations  # noqa: E402
from celery.schedules import crontab  # noqa: E402
from sqlalchemy import event, select, text  # noqa: E402
from sqlalchemy.ext.asyncio import (  # noqa: E402
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool  # noqa: E402

from src.celery import beat_schedule  # noqa: E402
from src.celery.tasks import webhook_dlq_replay as task_module  # noqa: E402
from src.celery_app import app as celery_app  # noqa: E402
from src.db.models import WebhookDlqEntry  # noqa: E402
from src.mcp.services.notifications import (  # noqa: E402
    webhook_dlq_persistence as dlq_dao,
)
from src.mcp.services.notifications.schemas import AdapterResult  # noqa: E402
from src.mcp.services.notifications.slack import SlackNotifier  # noqa: E402

# ---------------------------------------------------------------------------
# Constants — every magic value lives here so a future schema bump is a
# single-line edit at the top of the module.
# ---------------------------------------------------------------------------

_DAO_MODULE: str = "src.mcp.services.notifications.webhook_dlq_persistence"
_TASK_MODULE: str = "src.celery.tasks.webhook_dlq_replay"
_TESTS_DIR: Path = Path(__file__).resolve().parents[1]
_BACKEND_ROOT: Path = _TESTS_DIR.parent
_VERSIONS_DIR: Path = _BACKEND_ROOT / "alembic" / "versions"
_REVISION: str = "027"

#: Pinned "current instant" for every monkeypatched test.
_FIXED_NOW: datetime = datetime(2026, 4, 22, 12, 0, 0, tzinfo=UTC)

#: Beat-schedule entry name (must match the ``BEAT_SCHEDULE`` key).
_BEAT_ENTRY_NAME: str = "argus.notifications.webhook_dlq_replay"

#: Queue this task is routed onto (matches both ``BEAT_SCHEDULE.options.queue``
#: and the wildcard route ``argus.notifications.*`` in ``src.celery_app``).
_NOTIFICATIONS_QUEUE: str = "argus.notifications"


# ---------------------------------------------------------------------------
# Schema bootstrap — apply Alembic revision 027 against in-memory SQLite.
# Mirrors ``tests/notifications/test_webhook_dlq_persistence.py``.
# ---------------------------------------------------------------------------


def _load_revision_module() -> Any:
    """Import revision 027 as a standalone module (no full chain run).

    Returning ``Any`` is deliberate: ``upgrade`` / ``downgrade`` are free
    functions on the migration script and have no public type stubs.
    """
    matches = list(_VERSIONS_DIR.glob(f"{_REVISION}_*.py"))
    assert matches, (
        f"revision {_REVISION} not found under {_VERSIONS_DIR}"
    )
    spec = importlib.util.spec_from_file_location(
        f"_alembic_{_REVISION}", matches[0]
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _bootstrap_schema_sync(conn: Any) -> None:
    """Create minimal ``tenants`` table + apply revision 027."""
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
# Engine + session factory fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    """Per-test in-memory async SQLite engine with revision 027 applied.

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
def session_factory(
    engine: AsyncEngine,
) -> async_sessionmaker[AsyncSession]:
    """Session factory bound to the per-test SQLite engine."""
    return async_sessionmaker(engine, expire_on_commit=False)


# ---------------------------------------------------------------------------
# Engine-factory monkeypatch.
# ---------------------------------------------------------------------------


class _NoDisposeEngine:
    """Stand-in for ``AsyncEngine`` whose only public surface is ``dispose``.

    The task body calls ``await engine.dispose()`` in a ``finally`` to release
    the asyncpg pool in production. In tests we own the engine lifecycle via
    the ``engine`` fixture and want the in-memory DB to survive past ``_run``
    so the assertions can re-open a session against the same engine. This
    wrapper is what the monkeypatched ``create_task_engine_and_session``
    returns; the *real* engine is reachable via the ``session_factory``
    fixture which the test wires into the task module separately.
    """

    async def dispose(self) -> None:
        """No-op so the test-owned engine stays alive past ``_run``."""
        return None


@pytest.fixture
def patch_task_engine(
    session_factory: async_sessionmaker[AsyncSession],
    monkeypatch: pytest.MonkeyPatch,
) -> async_sessionmaker[AsyncSession]:
    """Re-route ``create_task_engine_and_session`` to the in-memory engine.

    Returns the same ``session_factory`` so test bodies can both seed and
    assert against the per-test SQLite engine without re-deriving it.
    """
    fake_engine = _NoDisposeEngine()

    def _factory() -> tuple[Any, async_sessionmaker[AsyncSession]]:
        return fake_engine, session_factory

    monkeypatch.setattr(
        f"{_TASK_MODULE}.create_task_engine_and_session", _factory
    )
    return session_factory


@pytest.fixture
def freeze_dao_now(monkeypatch: pytest.MonkeyPatch) -> datetime:
    """Pin ``webhook_dlq_persistence._utcnow`` to :data:`_FIXED_NOW`.

    Required for any test that asserts on ``replayed_at`` / ``abandoned_at``
    instants, which the DAO writes via ``_utcnow()``.
    """
    monkeypatch.setattr(f"{_DAO_MODULE}._utcnow", lambda: _FIXED_NOW)
    return _FIXED_NOW


# ---------------------------------------------------------------------------
# Adapter stub helpers — match the ``NotifierBase`` surface that
# ``_replay_entry`` actually touches (``send_with_retry`` + ``aclose``).
# ---------------------------------------------------------------------------


def _adapter_result(
    *,
    delivered: bool,
    event_id: str,
    adapter_name: str = "slack",
    status_code: int | None = 200,
    error_code: str | None = None,
    skipped_reason: str | None = None,
) -> AdapterResult:
    """Build an :class:`AdapterResult` with the required minimum shape."""
    return AdapterResult(
        adapter_name=adapter_name,
        event_id=event_id,
        delivered=delivered,
        status_code=status_code if delivered else (status_code or 503),
        attempts=1,
        target_redacted="abcdef012345",
        error_code=error_code if not delivered else None,
        skipped_reason=skipped_reason,
        duplicate_of=None,
    )


def _adapter_stub(
    *,
    result: AdapterResult | None = None,
    raise_exc: BaseException | None = None,
) -> MagicMock:
    """Build a stub matching the ``NotifierBase`` surface used by ``_replay_entry``.

    Exactly one of ``result`` / ``raise_exc`` must be supplied. The stub
    exposes the two methods the task body actually calls: ``send_with_retry``
    (awaitable, returns the supplied :class:`AdapterResult` or raises) and
    ``aclose`` (awaitable, returns ``None``).
    """
    assert (result is None) != (raise_exc is None), (
        "exactly one of result / raise_exc must be supplied"
    )
    stub = MagicMock()
    if raise_exc is not None:
        stub.send_with_retry = AsyncMock(side_effect=raise_exc)
    else:
        stub.send_with_retry = AsyncMock(return_value=result)
    stub.aclose = AsyncMock(return_value=None)
    return stub


def _patch_adapter(
    monkeypatch: pytest.MonkeyPatch, adapter: MagicMock
) -> None:
    """Replace ``_build_adapter`` so every replay returns the supplied stub.

    The patch is at the *task module* level so ``_replay_entry``'s call
    resolves to the stub regardless of ``adapter_name``.
    """
    monkeypatch.setattr(
        f"{_TASK_MODULE}._build_adapter", lambda adapter_name: adapter
    )


# ---------------------------------------------------------------------------
# Seed helpers.
# ---------------------------------------------------------------------------


def _payload_for(event_id: str, tenant_id: str) -> dict[str, Any]:
    """Build a valid :class:`NotificationEvent` payload dict.

    Stored verbatim in ``payload_json``; ``_replay_entry`` validates it via
    ``NotificationEvent.model_validate`` before dispatch, so every field
    must satisfy the pydantic schema constraints.
    """
    return {
        "event_id": event_id,
        "event_type": "approval.pending",
        "severity": "medium",
        "title": "T40 test event",
        "summary": "deterministic test summary",
        "tenant_id": tenant_id,
    }


async def _seed_tenant(
    factory: async_sessionmaker[AsyncSession], *, name: str = "t40-tenant"
) -> str:
    """Insert a minimal ``tenants`` row and return the new id."""
    tid = str(uuid.uuid4())
    async with factory() as s:
        await s.execute(
            text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
            {"id": tid, "name": name},
        )
        await s.commit()
    return tid


async def _seed_dlq_row(
    factory: async_sessionmaker[AsyncSession],
    *,
    tenant_id: str,
    event_id: str,
    adapter_name: str = "slack",
    attempt_count: int = 0,
) -> WebhookDlqEntry:
    """Insert a DLQ row via the production DAO and return it."""
    async with factory() as s:
        entry = await dlq_dao.enqueue(
            s,
            tenant_id=tenant_id,
            adapter_name=adapter_name,
            event_type="approval.pending",
            event_id=event_id,
            target_url=f"https://hooks.slack.example/T0/B0/{event_id}",
            payload=_payload_for(event_id, tenant_id),
            last_error_code="http_5xx",
            last_status_code=503,
            attempt_count=attempt_count,
        )
        await s.commit()
        return entry


def _naive(dt: datetime) -> datetime:
    """Strip ``tzinfo`` so SQLite-readback comparisons line up.

    SQLite's ``DateTime(timezone=True)`` round-trips into naive datetimes —
    an aware-vs-naive comparison raises ``TypeError`` on assertion.
    """
    return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt


async def _force_columns(
    factory: async_sessionmaker[AsyncSession],
    *,
    entry_id: str,
    created_at: datetime | None = None,
    next_retry_at: datetime | None = None,
    replayed_at: datetime | None = None,
    abandoned_at: datetime | None = None,
) -> None:
    """Override server-default timestamps via raw UPDATE.

    ``created_at`` uses ``server_default=func.now()`` so the ORM never
    accepts an explicit value at INSERT time. Tests that depend on a
    specific creation instant (FIFO ordering, 14d cutoff) rewrite it here.
    """
    pairs: list[tuple[str, datetime]] = [
        (col, val)
        for col, val in (
            ("created_at", created_at),
            ("next_retry_at", next_retry_at),
            ("replayed_at", replayed_at),
            ("abandoned_at", abandoned_at),
        )
        if val is not None
    ]
    if not pairs:
        return
    set_clause = ", ".join(f"{col} = :{col}" for col, _ in pairs)
    params: dict[str, Any] = {"id": entry_id}
    for col, val in pairs:
        params[col] = _naive(val)
    async with factory() as s:
        await s.execute(
            text(
                f"UPDATE webhook_dlq_entries SET {set_clause} "
                f"WHERE id = :id"
            ),
            params,
        )
        await s.commit()


async def _fetch_row(
    factory: async_sessionmaker[AsyncSession], *, entry_id: str
) -> WebhookDlqEntry:
    """Load a single ``WebhookDlqEntry`` by id (post-``_run`` assertions)."""
    async with factory() as s:
        row = await s.scalar(
            select(WebhookDlqEntry).where(WebhookDlqEntry.id == entry_id)
        )
        assert row is not None, f"entry {entry_id!r} vanished"
        return row


# ===========================================================================
# Unit cases (4)
# ===========================================================================


class TestBeatScheduleRegistration:
    """Unit case 1 — ``BEAT_SCHEDULE`` entry shape + queue routing."""

    def test_beat_schedule_registers_webhook_dlq_replay_at_06_utc_on_notifications_queue(
        self,
    ) -> None:
        """Entry exists, fires daily at 06:00 UTC, options.queue is set.

        Also verifies the wildcard route ``argus.notifications.*`` is
        present on the Celery app so any task on this queue is dispatched
        to the dedicated worker pool (T40 acceptance criterion (a)).
        """
        entry = beat_schedule.BEAT_SCHEDULE.get(_BEAT_ENTRY_NAME)
        assert entry is not None, (
            f"{_BEAT_ENTRY_NAME!r} missing from BEAT_SCHEDULE"
        )
        assert entry["task"] == _BEAT_ENTRY_NAME

        sched = entry["schedule"]
        assert isinstance(sched, crontab), (
            f"schedule must be a crontab; got {type(sched).__name__}"
        )
        assert sched.hour == {6}, f"hour must be 06:00 UTC, got {sched.hour}"
        assert sched.minute == {0}, (
            f"minute must be 0 (top of hour), got {sched.minute}"
        )
        assert entry["options"] == {"queue": _NOTIFICATIONS_QUEUE}

        routes = celery_app.conf.task_routes
        assert "argus.notifications.*" in routes, (
            "wildcard route argus.notifications.* missing from "
            "celery_app.conf.task_routes"
        )
        assert routes["argus.notifications.*"] == {
            "queue": _NOTIFICATIONS_QUEUE
        }


class TestBuildAdapter:
    """Unit cases 3 & 4 — ``_build_adapter`` factory contract."""

    def test_build_adapter_slack_returns_slack_notifier_instance(self) -> None:
        """Known adapter name resolves to the matching :class:`NotifierBase`.

        T40 acceptance criterion (f) — adapter factory is the single seam
        the per-row replay uses; misrouting here would silently dispatch
        to the wrong upstream.
        """
        adapter = task_module._build_adapter("slack")
        try:
            assert isinstance(adapter, SlackNotifier)
            assert adapter.name == "slack"
        finally:
            # The Slack adapter holds an httpx client; close it so pytest
            # does not warn about an un-closed connector at teardown.
            import asyncio

            asyncio.run(adapter.aclose())

    def test_build_adapter_unknown_name_raises_value_error(self) -> None:
        """Unknown ``adapter_name`` is a row-corruption signal.

        The per-row handler in ``_replay_entry`` catches it and routes
        the row through ``_safe_increment_attempt`` with
        ``last_error_code="dispatch_exception"`` — but only if the factory
        raises a *recognisable* error. ``ValueError`` is the contract.
        """
        with pytest.raises(ValueError, match="unknown adapter_name"):
            task_module._build_adapter("nonexistent")


class TestRunReturnShape:
    """Unit case 2 — ``_run`` returns the documented dict shape."""

    async def test_run_with_empty_db_returns_three_zero_int_keys(
        self,
        patch_task_engine: async_sessionmaker[AsyncSession],
        freeze_dao_now: datetime,
    ) -> None:
        """No rows -> all three counters at zero, exact key set, all int.

        T40 acceptance criterion (f) — task body always returns the
        ``{replayed, failed, abandoned_max_age}`` dict, even when the
        replay loop processed nothing.
        """
        result = await task_module._run(now=_FIXED_NOW)
        assert result == {
            "replayed": 0,
            "failed": 0,
            "abandoned_max_age": 0,
        }
        assert set(result.keys()) == {
            "replayed",
            "failed",
            "abandoned_max_age",
        }
        for key, value in result.items():
            assert isinstance(value, int), (
                f"{key!r} must be int, got {type(value).__name__}"
            )


# ===========================================================================
# Integration cases (8) — drive ``await _run(now=fixed_t)`` against the
# in-memory SQLite engine + a stubbed adapter.
# ===========================================================================


class TestReplaySuccess:
    """Integration case 1 — happy-path replay."""

    async def test_due_row_with_delivered_true_marks_replayed_and_counts(
        self,
        patch_task_engine: async_sessionmaker[AsyncSession],
        freeze_dao_now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``next_retry_at <= now`` + adapter delivered -> ``mark_replayed``.

        Asserts both the per-row mutation (``replayed_at`` populated,
        ``abandoned_at`` left null) and the counter shape — T40
        acceptance criterion (c).
        """
        factory = patch_task_engine
        tenant_id = await _seed_tenant(factory)
        entry = await _seed_dlq_row(
            factory, tenant_id=tenant_id, event_id="evt-replay-success-01"
        )
        await _force_columns(
            factory,
            entry_id=entry.id,
            next_retry_at=_FIXED_NOW - timedelta(hours=1),
        )
        adapter = _adapter_stub(
            result=_adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        result = await task_module._run(now=_FIXED_NOW)

        assert result == {
            "replayed": 1,
            "failed": 0,
            "abandoned_max_age": 0,
        }
        adapter.send_with_retry.assert_awaited_once()
        adapter.aclose.assert_awaited_once()

        row = await _fetch_row(factory, entry_id=entry.id)
        assert row.replayed_at is not None, (
            "delivered=True must populate replayed_at via mark_replayed"
        )
        assert row.abandoned_at is None
        assert row.attempt_count == 0, (
            "mark_replayed must NOT bump attempt_count"
        )


class TestReplayFailure:
    """Integration case 2 — failure path (delivered=False)."""

    async def test_due_row_with_delivered_false_increments_attempt_and_counts(
        self,
        patch_task_engine: async_sessionmaker[AsyncSession],
        freeze_dao_now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``delivered=False`` -> ``increment_attempt`` with the actual
        ``error_code`` / ``status_code`` from the adapter result.

        T40 acceptance criterion (d) — attempt count and backoff reflow.
        """
        factory = patch_task_engine
        tenant_id = await _seed_tenant(factory)
        entry = await _seed_dlq_row(
            factory, tenant_id=tenant_id, event_id="evt-replay-fail-01"
        )
        await _force_columns(
            factory,
            entry_id=entry.id,
            next_retry_at=_FIXED_NOW - timedelta(hours=1),
        )
        adapter = _adapter_stub(
            result=_adapter_result(
                delivered=False,
                event_id=entry.event_id,
                error_code="http_5xx",
                status_code=502,
            )
        )
        _patch_adapter(monkeypatch, adapter)

        result = await task_module._run(now=_FIXED_NOW)

        assert result == {
            "replayed": 0,
            "failed": 1,
            "abandoned_max_age": 0,
        }
        adapter.send_with_retry.assert_awaited_once()
        adapter.aclose.assert_awaited_once()

        row = await _fetch_row(factory, entry_id=entry.id)
        assert row.attempt_count == 1, (
            "delivered=False must bump attempt_count via increment_attempt"
        )
        assert row.last_error_code == "http_5xx"
        assert row.last_status_code == 502
        assert row.replayed_at is None
        assert row.abandoned_at is None
        # ``compute_next_retry_at(attempt_count=1)`` -> +120s from _FIXED_NOW.
        assert row.next_retry_at == _naive(
            _FIXED_NOW + timedelta(seconds=120)
        )


class TestReplayException:
    """Integration case 3 — adapter raises (transport / corruption)."""

    async def test_dispatch_exception_absorbed_and_logged_as_dispatch_exception(
        self,
        patch_task_engine: async_sessionmaker[AsyncSession],
        freeze_dao_now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``send_with_retry`` raising MUST NOT surface from ``_run``.

        T40 acceptance criterion (f) — per-row failures absorbed, counter
        ``failed`` incremented, ``last_error_code`` set to the
        closed-taxonomy ``dispatch_exception`` short-id.
        """
        factory = patch_task_engine
        tenant_id = await _seed_tenant(factory)
        entry = await _seed_dlq_row(
            factory, tenant_id=tenant_id, event_id="evt-replay-exc-01"
        )
        await _force_columns(
            factory,
            entry_id=entry.id,
            next_retry_at=_FIXED_NOW - timedelta(hours=1),
        )
        adapter = _adapter_stub(raise_exc=RuntimeError("boom"))
        _patch_adapter(monkeypatch, adapter)

        result = await task_module._run(now=_FIXED_NOW)

        assert result == {
            "replayed": 0,
            "failed": 1,
            "abandoned_max_age": 0,
        }
        adapter.send_with_retry.assert_awaited_once()
        adapter.aclose.assert_awaited_once(), (
            "aclose must run via the finally even when send_with_retry raises"
        )

        row = await _fetch_row(factory, entry_id=entry.id)
        assert row.attempt_count == 1
        assert row.last_error_code == "dispatch_exception", (
            "task-body exception path must use the dispatch_exception "
            "closed-taxonomy short-id"
        )
        assert row.last_status_code is None
        assert row.replayed_at is None
        assert row.abandoned_at is None


class TestPendingNotDueSkip:
    """Integration case 4 — ``next_retry_at`` in the future is skipped."""

    async def test_future_next_retry_at_row_is_not_picked_up(
        self,
        patch_task_engine: async_sessionmaker[AsyncSession],
        freeze_dao_now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Row with ``next_retry_at = now + 1h`` must not be replayed.

        T40 acceptance criterion (b) — replay batch filter respects
        ``next_retry_at <= now``.
        """
        factory = patch_task_engine
        tenant_id = await _seed_tenant(factory)
        entry = await _seed_dlq_row(
            factory, tenant_id=tenant_id, event_id="evt-pending-future-01"
        )
        await _force_columns(
            factory,
            entry_id=entry.id,
            next_retry_at=_FIXED_NOW + timedelta(hours=1),
        )
        adapter = _adapter_stub(
            result=_adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        result = await task_module._run(now=_FIXED_NOW)

        assert result == {
            "replayed": 0,
            "failed": 0,
            "abandoned_max_age": 0,
        }
        adapter.send_with_retry.assert_not_awaited()

        row = await _fetch_row(factory, entry_id=entry.id)
        assert row.replayed_at is None
        assert row.abandoned_at is None
        assert row.attempt_count == 0


class TestReplayedSkip:
    """Integration case 5 — already-replayed row is skipped."""

    async def test_row_with_replayed_at_set_is_not_picked_up(
        self,
        patch_task_engine: async_sessionmaker[AsyncSession],
        freeze_dao_now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Terminal ``replayed_at`` excludes the row from both batches.

        T40 acceptance criterion (b) — terminal rows never re-dispatch.
        """
        factory = patch_task_engine
        tenant_id = await _seed_tenant(factory)
        entry = await _seed_dlq_row(
            factory, tenant_id=tenant_id, event_id="evt-already-replayed-01"
        )
        await _force_columns(
            factory,
            entry_id=entry.id,
            next_retry_at=_FIXED_NOW - timedelta(hours=1),
            replayed_at=_FIXED_NOW - timedelta(hours=1),
        )
        adapter = _adapter_stub(
            result=_adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        result = await task_module._run(now=_FIXED_NOW)

        assert result == {
            "replayed": 0,
            "failed": 0,
            "abandoned_max_age": 0,
        }
        adapter.send_with_retry.assert_not_awaited()


class TestAbandonedSkip:
    """Integration case 6 — already-abandoned row is skipped."""

    async def test_row_with_abandoned_at_set_is_not_picked_up(
        self,
        patch_task_engine: async_sessionmaker[AsyncSession],
        freeze_dao_now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Terminal ``abandoned_at`` excludes the row from both batches.

        T40 acceptance criterion (b) — terminal rows never re-dispatch.
        """
        factory = patch_task_engine
        tenant_id = await _seed_tenant(factory)
        entry = await _seed_dlq_row(
            factory, tenant_id=tenant_id, event_id="evt-already-abandoned-01"
        )
        await _force_columns(
            factory,
            entry_id=entry.id,
            next_retry_at=_FIXED_NOW - timedelta(hours=1),
            abandoned_at=_FIXED_NOW - timedelta(hours=1),
        )
        adapter = _adapter_stub(
            result=_adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        result = await task_module._run(now=_FIXED_NOW)

        assert result == {
            "replayed": 0,
            "failed": 0,
            "abandoned_max_age": 0,
        }
        adapter.send_with_retry.assert_not_awaited()


class TestAbandonAged:
    """Integration case 7 — aged-out row routed through ``mark_abandoned``."""

    async def test_aged_row_marked_abandoned_with_max_age_reason(
        self,
        patch_task_engine: async_sessionmaker[AsyncSession],
        freeze_dao_now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``created_at <= now - DLQ_MAX_AGE_DAYS`` -> abandon batch.

        Adapter MUST NOT be called — the abandon path bypasses dispatch.
        T40 acceptance criterion (e).
        """
        factory = patch_task_engine
        tenant_id = await _seed_tenant(factory)
        entry = await _seed_dlq_row(
            factory, tenant_id=tenant_id, event_id="evt-aged-01"
        )
        await _force_columns(
            factory,
            entry_id=entry.id,
            created_at=_FIXED_NOW - timedelta(days=15),
            next_retry_at=_FIXED_NOW + timedelta(hours=1),
        )
        adapter = _adapter_stub(
            result=_adapter_result(delivered=True, event_id=entry.event_id)
        )
        _patch_adapter(monkeypatch, adapter)

        result = await task_module._run(now=_FIXED_NOW)

        assert result == {
            "replayed": 0,
            "failed": 0,
            "abandoned_max_age": 1,
        }
        adapter.send_with_retry.assert_not_awaited()

        row = await _fetch_row(factory, entry_id=entry.id)
        assert row.abandoned_at is not None
        assert row.abandoned_reason == "max_age"
        assert row.replayed_at is None


class TestMixedBatch:
    """Integration case 8 — every row state in one tick."""

    async def test_mixed_batch_routes_each_row_to_the_correct_path(
        self,
        patch_task_engine: async_sessionmaker[AsyncSession],
        freeze_dao_now: datetime,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """4 rows: due-success + due-failure + aged + future-pending.

        Single ``_run`` tick must:
          * deliver the success row -> ``replayed=1``;
          * bump the failure row -> ``failed=1``;
          * abandon the aged row -> ``abandoned_max_age=1``;
          * leave the future-pending row untouched.

        Verifies the loop body does NOT short-circuit on a per-row
        failure (T40 acceptance criterion (f)).
        """
        factory = patch_task_engine
        tenant_id = await _seed_tenant(factory)

        success = await _seed_dlq_row(
            factory, tenant_id=tenant_id, event_id="evt-mixed-success"
        )
        await _force_columns(
            factory,
            entry_id=success.id,
            next_retry_at=_FIXED_NOW - timedelta(hours=1),
        )
        fail = await _seed_dlq_row(
            factory, tenant_id=tenant_id, event_id="evt-mixed-fail-row"
        )
        await _force_columns(
            factory,
            entry_id=fail.id,
            next_retry_at=_FIXED_NOW - timedelta(hours=1),
        )
        aged = await _seed_dlq_row(
            factory, tenant_id=tenant_id, event_id="evt-mixed-aged-row"
        )
        await _force_columns(
            factory,
            entry_id=aged.id,
            created_at=_FIXED_NOW - timedelta(days=15),
            next_retry_at=_FIXED_NOW + timedelta(hours=1),
        )
        future = await _seed_dlq_row(
            factory, tenant_id=tenant_id, event_id="evt-mixed-future"
        )
        await _force_columns(
            factory,
            entry_id=future.id,
            next_retry_at=_FIXED_NOW + timedelta(hours=2),
        )

        # Per-event_id routing: success row -> delivered=True;
        # fail row -> delivered=False with http_5xx.
        success_event_id = success.event_id
        fail_event_id = fail.event_id
        success_result = _adapter_result(
            delivered=True, event_id=success_event_id
        )
        fail_result = _adapter_result(
            delivered=False,
            event_id=fail_event_id,
            error_code="http_5xx",
            status_code=503,
        )

        async def _route(
            event: Any, *, tenant_id: str
        ) -> AdapterResult:  # noqa: ARG001 — match NotifierBase.send_with_retry signature
            if event.event_id == success_event_id:
                return success_result
            if event.event_id == fail_event_id:
                return fail_result
            raise AssertionError(
                f"unexpected event_id reached the adapter: {event.event_id!r}"
            )

        adapter = MagicMock()
        adapter.send_with_retry = AsyncMock(side_effect=_route)
        adapter.aclose = AsyncMock(return_value=None)
        _patch_adapter(monkeypatch, adapter)

        result = await task_module._run(now=_FIXED_NOW)

        assert result == {
            "replayed": 1,
            "failed": 1,
            "abandoned_max_age": 1,
        }
        # Two dispatches (success + fail), two aclose calls (one per replay).
        assert adapter.send_with_retry.await_count == 2
        assert adapter.aclose.await_count == 2

        success_row = await _fetch_row(factory, entry_id=success.id)
        fail_row = await _fetch_row(factory, entry_id=fail.id)
        aged_row = await _fetch_row(factory, entry_id=aged.id)
        future_row = await _fetch_row(factory, entry_id=future.id)

        assert success_row.replayed_at is not None
        assert success_row.abandoned_at is None

        assert fail_row.attempt_count == 1
        assert fail_row.last_error_code == "http_5xx"
        assert fail_row.last_status_code == 503
        assert fail_row.replayed_at is None
        assert fail_row.abandoned_at is None

        assert aged_row.abandoned_at is not None
        assert aged_row.abandoned_reason == "max_age"
        assert aged_row.replayed_at is None

        # Future-pending row must be byte-identical to seed state.
        assert future_row.replayed_at is None
        assert future_row.abandoned_at is None
        assert future_row.attempt_count == 0
