r"""WB-P1b — Postgres RLS + repository integration for Web Workbench projects.

Postgres-only tests that drive the real :class:`WorkbenchProjectRepository`
through ``AsyncSession`` with ``SET LOCAL app.current_tenant_id`` and assert the
migration-045 ``tenant_isolation`` FORCE policy isolates ``wb_projects`` /
``wb_scope_rules`` across tenants end-to-end (not just via the DAO's explicit
``tenant_id`` filter — a raw cross-tenant ``SELECT count(*)`` proves RLS bites).

Skip behaviour mirrors ``tests/db/test_webhook_dlq_rls.py`` verbatim so the two
modules share the same DATABASE_URL contract.

Run locally (PowerShell)::

    docker run --rm -d --name argus-pg-wb -p 55432:5432 `
        -e POSTGRES_PASSWORD=argus -e POSTGRES_DB=argus_test postgres:15
    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/web_workbench/test_projects_rls.py -v
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

from src.policy.audit import AuditLogger, InMemoryAuditSink
from src.policy.engagement_authorization import EngagementAuthorizationService
from src.policy.scope import ScopeKind, ScopeRule
from src.sandbox.signing import KeyManager
from src.web_workbench.contracts import WorkbenchProjectCreate
from src.web_workbench.projects.repository import (
    EapRejectedError,
    WorkbenchProjectRepository,
)

_BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]

_PG_URL_RAW: str = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL: bool = _PG_URL_RAW.startswith(("postgresql://", "postgresql+", "postgres://"))

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason=(
        "DATABASE_URL is not a Postgres URL — WB project RLS integration needs "
        "a real Postgres backend (set DATABASE_URL=postgresql+asyncpg://...)"
    ),
)


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


def _project_create(name: str) -> WorkbenchProjectCreate:
    return WorkbenchProjectCreate(
        name=name,
        scope_rules=(
            ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),
            ScopeRule(kind=ScopeKind.HOST, pattern="staging.example.com", deny=True),
        ),
    )


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_wb_projects_rls_cross_tenant_isolation(
    async_engine: AsyncEngine,
) -> None:
    """A tenant session sees only its own projects and scope rules via RLS."""
    sync_url = _to_sync_url(str(async_engine.url))
    tenant_a = _seed_tenant_sync(sync_url, "wb-rls-a")
    tenant_b = _seed_tenant_sync(sync_url, "wb-rls-b")
    repo = WorkbenchProjectRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        dto_a = await repo.create(s, tenant_a, _project_create("app-a"))

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_b)
        await repo.create(s, tenant_b, _project_create("app-b"))

    # tenant_b cannot read tenant_a's project by id, and its own list has 1.
    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_b)
        assert await repo.get(s, tenant_b, dto_a.id) is None
        items_b, total_b = await repo.list(s, tenant_b)
        assert total_b == 1
        assert items_b[0].name == "app-b"
        # Raw, unfiltered count proves RLS (not just the DAO tenant filter).
        raw = await s.execute(text("SELECT count(*) FROM wb_projects"))
        assert raw.scalar_one() == 1
        raw_rules = await s.execute(text("SELECT count(*) FROM wb_scope_rules"))
        assert raw_rules.scalar_one() == 2

    # tenant_a symmetric guarantee.
    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        items_a, total_a = await repo.list(s, tenant_a)
        assert total_a == 1
        assert items_a[0].id == dto_a.id
        raw = await s.execute(text("SELECT count(*) FROM wb_projects"))
        assert raw.scalar_one() == 1


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_wb_project_optimistic_lock_conflict(
    async_engine: AsyncEngine,
) -> None:
    """A stale ``expected_version`` update is rejected (no lost update)."""
    from src.web_workbench.contracts import WorkbenchProjectUpdate
    from src.web_workbench.projects.repository import OptimisticLockError

    sync_url = _to_sync_url(str(async_engine.url))
    tenant = _seed_tenant_sync(sync_url, "wb-lock")
    repo = WorkbenchProjectRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        dto = await repo.create(s, tenant, _project_create("app"))
        assert dto.version == 1

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        updated = await repo.update(
            s, tenant, dto.id, WorkbenchProjectUpdate(expected_version=1, name="renamed")
        )
        assert updated.version == 2
        assert updated.name == "renamed"

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        with pytest.raises(OptimisticLockError):
            await repo.update(
                s,
                tenant,
                dto.id,
                WorkbenchProjectUpdate(expected_version=1, name="stale"),
            )


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_wb_attach_eap_fail_closed_without_keys(
    async_engine: AsyncEngine, tmp_path: Path
) -> None:
    """An unsigned/unverifiable EAP is rejected fail-closed (no keys loaded)."""
    sync_url = _to_sync_url(str(async_engine.url))
    tenant = _seed_tenant_sync(sync_url, "wb-eap")
    repo = WorkbenchProjectRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    key_manager = KeyManager(tmp_path / "empty_keys")  # missing dir -> 0 keys
    key_manager.load()
    eap_service = EngagementAuthorizationService(
        key_manager=key_manager, audit_logger=AuditLogger(InMemoryAuditSink())
    )

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        dto = await repo.create(s, tenant, _project_create("app"))

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        with pytest.raises(EapRejectedError):
            await repo.attach_eap(
                s,
                tenant,
                dto.id,
                {"engagement_id": "eng-1", "not": "signed"},
                eap_service=eap_service,
            )
