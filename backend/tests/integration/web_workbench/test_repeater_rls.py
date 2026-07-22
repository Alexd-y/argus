r"""WB-P3b-2 — Postgres RLS + repository integration for repeater tables.

Drives :class:`RepeaterRepository` (+ the scope-gated :class:`RepeaterService`)
through ``AsyncSession`` with ``SET LOCAL app.current_tenant_id`` and asserts
migration-049 ``tenant_isolation`` FORCE policy isolates ``wb_repeater_tabs`` /
``wb_repeater_exchanges`` across tenants (raw cross-tenant ``count(*)`` proves
RLS, not just the DAO filter). Also covers optimistic locking and the
replay→record path — crucially that an out-of-scope replay records a *blocked*
exchange without ever invoking the sender.

Run locally (PowerShell)::

    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/web_workbench/test_repeater_rls.py -v
"""

from __future__ import annotations

import base64
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
from src.web_workbench.contracts.repeater import RepeaterTabCreate, RepeaterTabUpdate
from src.web_workbench.projects.repository import WorkbenchProjectRepository
from src.web_workbench.projects.service import ProjectScopeService
from src.web_workbench.proxy.transport import NormalizedRequest
from src.web_workbench.repeater.engine import RawResponse, RepeaterService
from src.web_workbench.repeater.repository import (
    OptimisticLockError,
    RepeaterRepository,
)

_BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]

_PG_URL_RAW: str = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL: bool = _PG_URL_RAW.startswith(("postgresql://", "postgresql+", "postgres://"))

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason="DATABASE_URL is not a Postgres URL — WB repeater RLS needs Postgres",
)

_IN_SCOPE = b"GET https://app.example.com/health HTTP/1.1\r\nHost: app.example.com\r\n\r\n"
_OUT_OF_SCOPE = b"GET https://evil.test/steal HTTP/1.1\r\nHost: evil.test\r\n\r\n"


class _CountingSender:
    """In-memory sender that records call count (must be 0 on a blocked replay)."""

    def __init__(self) -> None:
        self.calls = 0

    def send(self, request: NormalizedRequest, body: bytes) -> RawResponse:
        self.calls += 1
        return RawResponse(status_code=200, raw=b"HTTP/1.1 200 OK\r\n\r\nok", duration_ms=1)


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


def _tab(name: str, raw: bytes) -> RepeaterTabCreate:
    return RepeaterTabCreate(name=name, raw_request_base64=base64.b64encode(raw).decode())


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_repeater_cross_tenant_isolation(async_engine: AsyncEngine) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant_a = _seed_tenant_sync(sync_url, "wb-rep-a")
    tenant_b = _seed_tenant_sync(sync_url, "wb-rep-b")
    projects = WorkbenchProjectRepository()
    repo = RepeaterRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        proj_a = await projects.create(s, tenant_a, _project("app-a"))
        tab = await repo.create_tab(
            s, tenant_a, proj_a.id, _tab("t1", _IN_SCOPE), raw_request=_IN_SCOPE
        )
        service = RepeaterService(ProjectScopeService(proj_a.scope_rules))
        result = service.replay(_IN_SCOPE, _CountingSender())
        await repo.record_exchange(
            s, tenant_a, project_id=proj_a.id, tab_id=tab.id, raw_request=_IN_SCOPE, result=result
        )

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_b)
        proj_b = await projects.create(s, tenant_b, _project("app-b"))
        assert await repo.list_tabs(s, tenant_b, proj_b.id) == []
        raw_tabs = await s.execute(text("SELECT count(*) FROM wb_repeater_tabs"))
        assert raw_tabs.scalar_one() == 0
        raw_ex = await s.execute(text("SELECT count(*) FROM wb_repeater_exchanges"))
        assert raw_ex.scalar_one() == 0

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        tabs = await repo.list_tabs(s, tenant_a, proj_a.id)
        assert len(tabs) == 1
        items, total = await repo.list_exchanges(s, tenant_a, tabs[0].id)
        assert total == 1
        assert items[0].forward_outcome == "forward"


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_tab_optimistic_lock(async_engine: AsyncEngine) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant = _seed_tenant_sync(sync_url, "wb-rep-lock")
    projects = WorkbenchProjectRepository()
    repo = RepeaterRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        proj = await projects.create(s, tenant, _project("app"))
        tab = await repo.create_tab(
            s, tenant, proj.id, _tab("t1", _IN_SCOPE), raw_request=_IN_SCOPE
        )
        assert tab.version == 1

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        updated = await repo.update_tab(
            s,
            tenant,
            tab.id,
            RepeaterTabUpdate(expected_version=1, name="renamed"),
            raw_request=None,
        )
        assert updated.version == 2

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        with pytest.raises(OptimisticLockError):
            await repo.update_tab(
                s,
                tenant,
                tab.id,
                RepeaterTabUpdate(expected_version=1, name="stale"),
                raw_request=None,
            )


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_out_of_scope_replay_records_blocked_without_sending(
    async_engine: AsyncEngine,
) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant = _seed_tenant_sync(sync_url, "wb-rep-scope")
    projects = WorkbenchProjectRepository()
    repo = RepeaterRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        proj = await projects.create(s, tenant, _project("app"))
        tab = await repo.create_tab(
            s, tenant, proj.id, _tab("t1", _OUT_OF_SCOPE), raw_request=_OUT_OF_SCOPE
        )
        service = RepeaterService(ProjectScopeService(proj.scope_rules))
        sender = _CountingSender()
        result = service.replay(_OUT_OF_SCOPE, sender)

        # SI-WB-1: blocked replay never touches the sender.
        assert sender.calls == 0
        assert result.forwarded is False

        exchange = await repo.record_exchange(
            s, tenant, project_id=proj.id, tab_id=tab.id, raw_request=_OUT_OF_SCOPE, result=result
        )
        assert exchange.forward_outcome == "blocked"
        assert exchange.block_reason == "out_of_scope"
        assert exchange.status_code is None

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        items, total = await repo.list_exchanges(s, tenant, tab.id)
        assert total == 1
        assert items[0].forward_outcome == "blocked"
