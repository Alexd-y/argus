r"""WB-P4b — Postgres RLS + repository integration for intruder tables.

Drives :class:`IntruderRepository` through ``AsyncSession`` with
``SET LOCAL app.current_tenant_id`` and asserts migration-051 ``tenant_isolation``
FORCE policy isolates ``wb_intruder_attacks`` / ``wb_intruder_requests`` across
tenants (raw cross-tenant ``count(*)`` proves RLS, not just the DAO filter).
Also covers optimistic locking on user-driven status transitions and the
metadata-only result append.

Run locally (PowerShell)::

    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/web_workbench/test_intruder_rls.py -v
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
from src.web_workbench.intruder.repository import (
    STATUS_QUEUED,
    IntruderRepository,
    OptimisticLockError,
)
from src.web_workbench.projects.repository import WorkbenchProjectRepository

_BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]

_PG_URL_RAW: str = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL: bool = _PG_URL_RAW.startswith(("postgresql://", "postgresql+", "postgres://"))

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason="DATABASE_URL is not a Postgres URL — WB intruder RLS needs Postgres",
)

_TEMPLATE = b"GET https://app.example.com/?q={{x}} HTTP/1.1\r\nHost: app.example.com\r\n\r\n"


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
async def test_intruder_cross_tenant_isolation(async_engine: AsyncEngine) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant_a = _seed_tenant_sync(sync_url, "wb-intr-a")
    tenant_b = _seed_tenant_sync(sync_url, "wb-intr-b")
    projects = WorkbenchProjectRepository()
    repo = IntruderRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        proj_a = await projects.create(s, tenant_a, _project("app-a"))
        attack = await repo.create_attack(
            s,
            tenant_a,
            proj_a.id,
            name="atk1",
            attack_type="sniper",
            raw_request_template=_TEMPLATE,
            payload_config={"sets": [{"family_id": "xss_basic"}]},
        )
        await repo.record_request(
            s,
            tenant_a,
            project_id=proj_a.id,
            attack_id=attack.id,
            request_index=0,
            forward_outcome="forward",
            payload_label="xss_basic#p0",
            payload_index=0,
            status_code=200,
            response_length=12,
            flagged=True,
        )

    # Tenant B sees nothing — RLS FORCE, proven with a raw count(*).
    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_b)
        proj_b = await projects.create(s, tenant_b, _project("app-b"))
        assert await repo.list_attacks(s, tenant_b, proj_b.id) == []
        raw_atk = await s.execute(text("SELECT count(*) FROM wb_intruder_attacks"))
        assert raw_atk.scalar_one() == 0
        raw_req = await s.execute(text("SELECT count(*) FROM wb_intruder_requests"))
        assert raw_req.scalar_one() == 0

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        attacks = await repo.list_attacks(s, tenant_a, proj_a.id)
        assert len(attacks) == 1
        items, total = await repo.list_requests(s, tenant_a, attacks[0].id)
        assert total == 1
        assert items[0].flagged is True
        assert items[0].payload_index == 0


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_attack_status_optimistic_lock(async_engine: AsyncEngine) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant = _seed_tenant_sync(sync_url, "wb-intr-lock")
    projects = WorkbenchProjectRepository()
    repo = IntruderRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        proj = await projects.create(s, tenant, _project("app"))
        attack = await repo.create_attack(
            s,
            tenant,
            proj.id,
            name="atk",
            attack_type="sniper",
            raw_request_template=_TEMPLATE,
        )
        assert attack.version == 1
        assert attack.status == STATUS_QUEUED

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        updated = await repo.set_status(s, tenant, attack.id, "cancelled", expected_version=1)
        assert updated.version == 2
        assert updated.status == "cancelled"

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        with pytest.raises(OptimisticLockError):
            await repo.set_status(s, tenant, attack.id, "paused", expected_version=1)
