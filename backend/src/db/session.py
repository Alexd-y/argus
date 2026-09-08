"""Async database session — SQLAlchemy 2.0 + asyncpg / aiosqlite (test).

The module exposes a single ``engine`` plus an ``async_session_factory`` for
the FastAPI app and a ``create_task_engine_and_session()`` factory for Celery
workers (which need engines bound to their own event loop to dodge
``Future attached to different loop`` errors with asyncpg).

Pooling rules
-------------
* **PostgreSQL (production / CI):** ``QueuePool``-based engine with
  ``pool_pre_ping=True``, ``pool_size=5``, ``max_overflow=10``.
* **SQLite (in-memory unit tests):** ``StaticPool`` — the only safe choice
  for ``sqlite+aiosqlite:///:memory:`` because the in-memory DB is bound to
  a *single* connection and SQLite rejects ``pool_size`` / ``max_overflow``
  kwargs at engine construction time.

Switching pool kwargs by dialect keeps production behaviour byte-identical
while letting the test suite point ``DATABASE_URL`` at SQLite without the
``Invalid argument(s) 'pool_size','max_overflow'`` ``TypeError`` that has
been blocking ARG-028.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import AsyncGenerator
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import StaticPool

from src.core.config import settings
from src.db.models import Base

# PostgreSQL SET LOCAL does not support bound parameters ($1).
# We must embed the value; tenant_id is validated as UUID to prevent injection.


def _validate_tenant_id(tenant_id: str) -> str:
    """Validate tenant_id is a UUID. Raises ValueError if invalid."""
    uuid.UUID(tenant_id)
    return tenant_id


def _json_default(obj: Any) -> Any:
    """JSON fallback for values Postgres JSONB columns may receive.

    Pipeline phase outputs can embed rich objects (e.g. an ExploitationQueue
    with a ``created_at`` datetime). The stdlib encoder raises TypeError on
    those, which previously killed a whole scan at the phase_outputs INSERT.
    Encode the common non-JSON types deterministically; fall back to ``str``
    so a stray object degrades to a string rather than aborting the scan.
    """
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, uuid.UUID):
        return str(obj)
    if isinstance(obj, Decimal):
        return float(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (set, frozenset)):
        return sorted(obj, key=str)
    if isinstance(obj, bytes):
        return obj.decode("utf-8", "replace")
    return str(obj)


def _json_serializer(value: Any) -> str:
    """JSONB serializer that tolerates datetime/UUID/Decimal/Enum/etc."""
    return json.dumps(value, default=_json_default)


def _is_sqlite_url(database_url: str) -> bool:
    """True when the DSN targets SQLite (sync or aiosqlite driver)."""
    return database_url.startswith("sqlite")


def _engine_kwargs_for(database_url: str) -> dict[str, Any]:
    """Return ``create_async_engine`` kwargs appropriate for the dialect.

    SQLite (especially ``:memory:``) cannot use ``QueuePool``-style pool
    knobs; SQLAlchemy raises ``TypeError`` if we pass ``pool_size`` /
    ``max_overflow`` together with the implicit ``StaticPool``. The test
    suite needs an in-memory DB that is shared across all sessions in the
    same process, which is exactly what ``StaticPool`` delivers.
    """
    if _is_sqlite_url(database_url):
        return {
            "echo": False,
            "poolclass": StaticPool,
            "connect_args": {"check_same_thread": False},
            "json_serializer": _json_serializer,
        }
    return {
        "echo": False,
        "pool_pre_ping": True,
        "pool_size": 5,
        "max_overflow": 10,
        "json_serializer": _json_serializer,
    }


def _build_engine(database_url: str) -> AsyncEngine:
    """Construct an ``AsyncEngine`` with dialect-appropriate pooling."""
    return create_async_engine(database_url, **_engine_kwargs_for(database_url))


engine: AsyncEngine = _build_engine(settings.database_url)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


def create_task_engine_and_session() -> tuple[
    AsyncEngine, async_sessionmaker[AsyncSession]
]:
    """Create engine + session factory bound to the current event loop.

    Used inside Celery tasks to avoid ``Future attached to different loop``
    with asyncpg. Caller MUST ``await engine.dispose()`` when done.
    """
    task_engine = _build_engine(settings.database_url)
    task_session_factory = async_sessionmaker(
        task_engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autocommit=False,
        autoflush=False,
    )
    return task_engine, task_session_factory


def _session_dialect_name(session: AsyncSession) -> str:
    """Return the SQLAlchemy dialect name for ``session``, or empty string."""
    bind = session.bind
    if bind is None:
        try:
            bind = session.get_bind()
        except (RuntimeError, AttributeError):
            return ""
    dialect = getattr(bind, "dialect", None)
    return str(getattr(dialect, "name", "") or "")


async def set_session_tenant(session: AsyncSession, tenant_id: str) -> None:
    """Set ``app.current_tenant_id`` for RLS policies.

    Must be called at the start of each DB operation when RLS is enabled.
    PostgreSQL ``SET LOCAL`` does not accept bound parameters; ``tenant_id``
    is validated as UUID to prevent injection.

    SQLite has no ``SET LOCAL`` / GUC — skip the statement after UUID checks
    so unit tests can exercise SQLAlchemy repositories in-memory.
    """
    _validate_tenant_id(tenant_id)
    if _session_dialect_name(session) == "sqlite":
        return
    escaped = tenant_id.replace("'", "''")
    await session.execute(text(f"SET LOCAL app.current_tenant_id = '{escaped}'"))


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields an async session with commit/rollback semantics."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create tables (dev only). Production uses Alembic migrations."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
