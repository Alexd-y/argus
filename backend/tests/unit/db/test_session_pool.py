"""ARG-028 — Unit tests for ``src.db.session`` dialect-aware pooling.

Pins the contract that:

* ``sqlite+aiosqlite://`` URLs build an engine backed by ``StaticPool`` —
  the only safe choice for in-memory SQLite (the engine constructor
  rejects ``pool_size`` / ``max_overflow`` for SQLite + StaticPool).
* PostgreSQL (``postgresql+asyncpg://``) URLs build an engine backed by
  the SQLAlchemy default async queue pool with ``size == 5`` (matches the
  long-standing production knob).
* ``create_task_engine_and_session()`` mirrors the same dialect dispatch
  so Celery workers do not regress on either dialect.

The tests deliberately do *not* open a connection: ``create_async_engine``
resolves the dialect/pool at construction time, which is exactly what we
want to assert. Skipping I/O keeps the suite hermetic and offline.
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.pool import StaticPool

from src.db.session import (
    _build_engine,
    _engine_kwargs_for,
    _is_sqlite_url,
    create_task_engine_and_session,
)


# ---------------------------------------------------------------------------
# _is_sqlite_url — dialect detector
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///:memory:",
        "sqlite+aiosqlite:///:memory:",
        "sqlite+aiosqlite:///./test.db",
        "sqlite+pysqlite:///./test.db",
    ],
)
def test_is_sqlite_url_recognises_all_sqlite_dsn_variants(url: str) -> None:
    assert _is_sqlite_url(url) is True


@pytest.mark.parametrize(
    "url",
    [
        "postgresql://argus:argus@localhost:5432/argus",
        "postgresql+asyncpg://argus:argus@localhost:5432/argus",
        "postgresql+psycopg2://argus:argus@localhost:5432/argus",
        "mysql://x:y@localhost/db",
    ],
)
def test_is_sqlite_url_rejects_non_sqlite_dsn(url: str) -> None:
    assert _is_sqlite_url(url) is False


# ---------------------------------------------------------------------------
# _engine_kwargs_for — dialect-aware kwargs
# ---------------------------------------------------------------------------


def test_engine_kwargs_for_sqlite_uses_static_pool_no_size_kwargs() -> None:
    kwargs = _engine_kwargs_for("sqlite+aiosqlite:///:memory:")
    assert kwargs["poolclass"] is StaticPool
    assert kwargs["connect_args"] == {"check_same_thread": False}
    # Critical: SQLite + StaticPool MUST NOT receive QueuePool knobs.
    assert "pool_size" not in kwargs
    assert "max_overflow" not in kwargs
    assert "pool_pre_ping" not in kwargs


def test_engine_kwargs_for_postgres_uses_queue_pool_kwargs() -> None:
    kwargs = _engine_kwargs_for("postgresql+asyncpg://argus:argus@localhost:5432/argus")
    assert kwargs["pool_size"] == 5
    assert kwargs["max_overflow"] == 10
    assert kwargs["pool_pre_ping"] is True
    # No SQLite-only options on the Postgres path.
    assert "poolclass" not in kwargs
    assert "connect_args" not in kwargs


# ---------------------------------------------------------------------------
# _build_engine — concrete engine assembly
# ---------------------------------------------------------------------------


def test_build_engine_sqlite_returns_static_pool_engine() -> None:
    eng = _build_engine("sqlite+aiosqlite:///:memory:")
    try:
        assert isinstance(eng, AsyncEngine)
        assert type(eng.pool).__name__ == "StaticPool"
    finally:
        # Best-effort sync dispose — engine never opened a real connection.
        eng.sync_engine.dispose()


def test_build_engine_postgres_returns_queue_pool_with_size_5() -> None:
    eng = _build_engine("postgresql+asyncpg://argus:argus@localhost:5432/argus")
    try:
        assert isinstance(eng, AsyncEngine)
        # SQLAlchemy 2.x async engines wrap QueuePool in AsyncAdaptedQueuePool.
        pool_name = type(eng.pool).__name__
        assert pool_name in {"QueuePool", "AsyncAdaptedQueuePool"}, pool_name
        # Lazy: pool.size() reflects configured slot count (== pool_size).
        assert eng.pool.size() == 5
    finally:
        eng.sync_engine.dispose()


# ---------------------------------------------------------------------------
# create_task_engine_and_session — Celery worker factory
# ---------------------------------------------------------------------------


def test_create_task_engine_and_session_mirrors_dialect_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SQLite DSN — task engine MUST also use StaticPool (no pool_size)."""
    from src.db import session as session_mod

    monkeypatch.setattr(
        session_mod.settings,
        "database_url",
        "sqlite+aiosqlite:///:memory:",
    )
    task_engine, factory = create_task_engine_and_session()
    try:
        assert type(task_engine.pool).__name__ == "StaticPool"
        assert factory.kw["expire_on_commit"] is False
        assert factory.kw["autocommit"] is False
        assert factory.kw["autoflush"] is False
    finally:
        task_engine.sync_engine.dispose()


def test_create_task_engine_and_session_postgres_dsn_keeps_pool_kwargs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PostgreSQL DSN — task engine MUST keep ``pool_size=5`` (production parity)."""
    from src.db import session as session_mod

    monkeypatch.setattr(
        session_mod.settings,
        "database_url",
        "postgresql+asyncpg://argus:argus@localhost:5432/argus",
    )
    task_engine, _factory = create_task_engine_and_session()
    try:
        pool_name = type(task_engine.pool).__name__
        assert pool_name in {"QueuePool", "AsyncAdaptedQueuePool"}
        assert task_engine.pool.size() == 5
    finally:
        task_engine.sync_engine.dispose()
