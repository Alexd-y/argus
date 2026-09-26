r"""Shared Postgres fixtures for Cairn integration tests (Phase 2+).

All tests here are ``requires_postgres`` and skip unless ``DATABASE_URL`` points at
a real Postgres with the ``vector`` extension available (the ARGUS schema uses
``JSONB`` + pgvector + RLS which SQLite cannot model).

Migrations run **once** per session (sync, outside any event loop); each test uses
its own freshly-seeded tenant so the shared schema stays isolated by RLS.

Run locally (PowerShell)::

    docker run --rm -d --name argus-pg-cairn -p 55432:5432 `
        -e POSTGRES_PASSWORD=argus -e POSTGRES_DB=argus_test pgvector/pgvector:pg15
    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest backend/tests/integration/cairn -v
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

_BACKEND_ROOT: Path = Path(__file__).resolve().parents[3]
_PG_URL_RAW: str = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL: bool = _PG_URL_RAW.startswith(("postgresql://", "postgresql+", "postgres://"))

pytestmark = pytest.mark.requires_postgres

skip_without_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason="DATABASE_URL is not a Postgres URL — Cairn integration needs real Postgres",
)


def _to_async_url(url: str) -> str:
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def _to_sync_url(url: str) -> str:
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://") :]
    return url


def _alembic_config(database_url: str) -> Config:
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


@pytest.fixture(scope="session")
def migrated_db() -> str:
    """Migrate the test database to head once for the whole session (sync)."""
    if not _HAS_POSTGRES_URL:
        pytest.skip("DATABASE_URL is not a Postgres URL")
    async_url = _to_async_url(_PG_URL_RAW)
    # env.py reads settings.database_url; point it at the test DB before migrating.
    from src.core import config as _cfg

    _cfg.settings.database_url = async_url
    command.upgrade(_alembic_config(async_url), "head")
    return async_url


@pytest_asyncio.fixture()
async def async_engine(migrated_db: str) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(migrated_db, future=True)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest.fixture()
def sm(async_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(async_engine, expire_on_commit=False)


_APP_ROLE = "cairn_rls_app"
_APP_PASSWORD = "cairn_rls_pw"


@pytest.fixture(scope="session")
def app_role_url(migrated_db: str) -> str:
    """Create a non-superuser login role and return an async DSN for it.

    RLS is bypassed by superusers, so the isolation test must connect as an
    ordinary role — mirroring how the app connects in production.
    """
    sync_url = _to_sync_url(_PG_URL_RAW)
    sync_engine = sa.create_engine(sync_url, future=True, isolation_level="AUTOCOMMIT")
    try:
        with sync_engine.connect() as conn:
            conn.execute(
                text(
                    f"DO $$ BEGIN IF NOT EXISTS ("
                    f"SELECT FROM pg_roles WHERE rolname = '{_APP_ROLE}') THEN "
                    f"CREATE ROLE {_APP_ROLE} LOGIN PASSWORD '{_APP_PASSWORD}' "
                    f"NOSUPERUSER NOBYPASSRLS; END IF; END $$;"
                )
            )
            conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {_APP_ROLE}"))
            conn.execute(
                text(
                    f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES "
                    f"IN SCHEMA public TO {_APP_ROLE}"
                )
            )
            conn.execute(
                text(f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {_APP_ROLE}")
            )
    finally:
        sync_engine.dispose()
    # swap credentials in the async URL
    raw = _to_async_url(_PG_URL_RAW)
    after_scheme = raw.split("://", 1)[1]
    host_part = after_scheme.split("@", 1)[1]
    return f"postgresql+asyncpg://{_APP_ROLE}:{_APP_PASSWORD}@{host_part}"


@pytest_asyncio.fixture()
async def app_engine(app_role_url: str) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(app_role_url, future=True)
    try:
        yield eng
    finally:
        await eng.dispose()


@pytest.fixture()
def app_sm(app_engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(app_engine, expire_on_commit=False)


def _seed_tenant_sync(sync_url: str, name: str) -> str:
    tid = str(uuid.uuid4())
    sync_engine = sa.create_engine(sync_url, future=True)
    try:
        with sync_engine.begin() as conn:
            conn.execute(
                text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
                {"id": tid, "name": name},
            )
    finally:
        sync_engine.dispose()
    return tid


@pytest.fixture()
def tenant_id(migrated_db: str) -> str:
    # Use the raw env URL — str(engine.url) masks the password as '***'.
    return _seed_tenant_sync(_to_sync_url(_PG_URL_RAW), f"cairn-{uuid.uuid4().hex[:8]}")


@pytest.fixture()
def seed_tenant(migrated_db: str):
    """Return a factory that seeds and returns a new tenant id."""
    sync_url = _to_sync_url(_PG_URL_RAW)

    def _factory(name: str | None = None) -> str:
        return _seed_tenant_sync(sync_url, name or f"cairn-{uuid.uuid4().hex[:8]}")

    return _factory
