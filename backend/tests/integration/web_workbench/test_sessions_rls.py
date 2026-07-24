r"""WB-P6b — Postgres RLS + repository integration for session tables.

Drives :class:`SessionRepository` through ``AsyncSession`` with
``SET LOCAL app.current_tenant_id`` and asserts migration-051 ``tenant_isolation``
FORCE policy isolates ``wb_session_macros`` / ``wb_session_principals`` across
tenants (raw cross-tenant ``count(*)`` proves RLS). Also covers optimistic
locking and split-plane secrets (SI-3): the schema exposes only ``secret_ref``
placeholders / a ``secrets_ref`` handle — never a raw credential column.

Run locally (PowerShell)::

    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/web_workbench/test_sessions_rls.py -v
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
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

from src.policy.scope import ScopeKind, ScopeRule
from src.web_workbench.contracts.project import WorkbenchProjectCreate
from src.web_workbench.projects.repository import WorkbenchProjectRepository
from src.web_workbench.sessions.repository import (
    OptimisticLockError,
    SessionRepository,
)

_BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]

_PG_URL_RAW: str = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL: bool = _PG_URL_RAW.startswith(("postgresql://", "postgresql+", "postgres://"))

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason="DATABASE_URL is not a Postgres URL — WB sessions RLS needs Postgres",
)

#: Split-plane invariant (SI-3): no raw-secret columns may exist on either table.
_FORBIDDEN_COLUMNS = ("password", "token", "secret", "credential")


def _alembic_config(database_url: str) -> Config:
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


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


@pytest.fixture()
def pg_url(monkeypatch: pytest.MonkeyPatch) -> str:
    async_url = _to_async_url(_PG_URL_RAW)
    monkeypatch.setenv("DATABASE_URL", async_url)
    from src.core import config as _cfg

    monkeypatch.setattr(_cfg.settings, "database_url", async_url)
    return async_url


@pytest.fixture()
def migrated_db(pg_url: str) -> Iterator[str]:
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")
    try:
        yield pg_url
    finally:
        command.downgrade(cfg, "base")


@pytest.fixture()
async def async_engine(migrated_db: str) -> AsyncIterator[AsyncEngine]:
    eng = create_async_engine(migrated_db, future=True)
    try:
        yield eng
    finally:
        await eng.dispose()


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


async def _set_session_tenant(session: AsyncSession, tenant_id: str) -> None:
    await session.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}'"))


def _project(name: str) -> WorkbenchProjectCreate:
    return WorkbenchProjectCreate(
        name=name,
        scope_rules=(ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),),
    )


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_sessions_cross_tenant_isolation(async_engine: AsyncEngine) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant_a = _seed_tenant_sync(sync_url, "wb-sess-a")
    tenant_b = _seed_tenant_sync(sync_url, "wb-sess-b")
    projects = WorkbenchProjectRepository()
    repo = SessionRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        proj_a = await projects.create(s, tenant_a, _project("app-a"))
        macro = await repo.create_macro(
            s,
            tenant_a,
            proj_a.id,
            name="login",
            steps=[{"method": "POST", "target": "/login", "body": "u={{secret_ref:user}}"}],
            match_rules={"status": 200},
        )
        await repo.create_principal(
            s,
            tenant_a,
            proj_a.id,
            name="owner1",
            role="owner",
            secrets_ref="vault://tenant-a/owner1",
            macro_id=macro.id,
        )

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_b)
        proj_b = await projects.create(s, tenant_b, _project("app-b"))
        assert await repo.list_macros(s, tenant_b, proj_b.id) == []
        assert await repo.list_principals(s, tenant_b, proj_b.id) == []
        raw_m = await s.execute(text("SELECT count(*) FROM wb_session_macros"))
        assert raw_m.scalar_one() == 0
        raw_p = await s.execute(text("SELECT count(*) FROM wb_session_principals"))
        assert raw_p.scalar_one() == 0

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        assert len(await repo.list_macros(s, tenant_a, proj_a.id)) == 1
        principals = await repo.list_principals(s, tenant_a, proj_a.id)
        assert len(principals) == 1
        assert principals[0].secrets_ref == "vault://tenant-a/owner1"


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_macro_optimistic_lock(async_engine: AsyncEngine) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant = _seed_tenant_sync(sync_url, "wb-sess-lock")
    projects = WorkbenchProjectRepository()
    repo = SessionRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        proj = await projects.create(s, tenant, _project("app"))
        macro = await repo.create_macro(s, tenant, proj.id, name="m1")
        assert macro.version == 1

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        updated = await repo.update_macro(s, tenant, macro.id, expected_version=1, name="renamed")
        assert updated.version == 2

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        with pytest.raises(OptimisticLockError):
            await repo.update_macro(s, tenant, macro.id, expected_version=1, name="stale")


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_no_raw_secret_columns(async_engine: AsyncEngine) -> None:
    """SI-3 — split-plane: neither session table exposes a raw-secret column."""
    async with async_engine.connect() as conn:
        for table in ("wb_session_macros", "wb_session_principals"):
            result = await conn.execute(
                text("SELECT column_name FROM information_schema.columns " "WHERE table_name = :t"),
                {"t": table},
            )
            columns = {row[0].lower() for row in result.fetchall()}
            for forbidden in _FORBIDDEN_COLUMNS:
                assert not any(
                    forbidden in c for c in columns
                ), f"{table} exposes a raw-secret column matching {forbidden!r}: {columns}"
