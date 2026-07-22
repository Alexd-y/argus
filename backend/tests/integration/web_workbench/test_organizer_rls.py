r"""WB-P3c — Postgres RLS + repository integration for organizer tables.

Drives :class:`OrganizerRepository` through ``AsyncSession`` with
``SET LOCAL app.current_tenant_id`` and asserts migration-048 ``tenant_isolation``
FORCE policy isolates ``wb_organizer_collections`` / ``wb_organizer_items`` across
tenants (raw cross-tenant ``count(*)`` proves RLS, not just the DAO filter). Also
covers optimistic locking, search (tag / host / title) and raw round-trip.

Run locally (PowerShell)::

    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/web_workbench/test_organizer_rls.py -v
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
from src.web_workbench.contracts.organizer import (
    OrganizerCollectionCreate,
    OrganizerCollectionUpdate,
    OrganizerItemCreate,
)
from src.web_workbench.contracts.project import WorkbenchProjectCreate
from src.web_workbench.organizer.repository import (
    OptimisticLockError,
    OrganizerRepository,
)
from src.web_workbench.projects.repository import WorkbenchProjectRepository

_BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]

_PG_URL_RAW: str = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL: bool = _PG_URL_RAW.startswith(("postgresql://", "postgresql+", "postgres://"))

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason="DATABASE_URL is not a Postgres URL — WB organizer RLS needs Postgres",
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


def _project(name: str) -> WorkbenchProjectCreate:
    return WorkbenchProjectCreate(
        name=name,
        scope_rules=(ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com"),),
    )


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_organizer_cross_tenant_isolation(async_engine: AsyncEngine) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant_a = _seed_tenant_sync(sync_url, "wb-org-a")
    tenant_b = _seed_tenant_sync(sync_url, "wb-org-b")
    projects = WorkbenchProjectRepository()
    org = OrganizerRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        proj_a = await projects.create(s, tenant_a, _project("app-a"))
        coll = await org.create_collection(
            s, tenant_a, proj_a.id, OrganizerCollectionCreate(name="Auth")
        )
        await org.create_item(
            s,
            tenant_a,
            coll.id,
            OrganizerItemCreate(title="login", host="app.example.com", tags=("auth",)),
            raw_request=b"POST /login HTTP/1.1\r\n\r\n",
            raw_response=None,
        )

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_b)
        proj_b = await projects.create(s, tenant_b, _project("app-b"))
        await org.create_collection(s, tenant_b, proj_b.id, OrganizerCollectionCreate(name="Auth"))
        # tenant_b sees none of tenant_a's items (RLS, raw count).
        items, total = await org.list_items(s, tenant_b, proj_b.id)
        assert total == 0
        assert items == []
        raw_items = await s.execute(text("SELECT count(*) FROM wb_organizer_items"))
        assert raw_items.scalar_one() == 0
        raw_coll = await s.execute(text("SELECT count(*) FROM wb_organizer_collections"))
        assert raw_coll.scalar_one() == 1  # only tenant_b's own collection

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        items, total = await org.list_items(s, tenant_a, proj_a.id)
        assert total == 1
        # list view withholds raw bytes but flags presence.
        assert items[0].has_raw_request is True
        assert items[0].raw_request_base64 is None
        # single-item GET returns the raw bytes byte-exact.
        detail = await org.get_item(s, tenant_a, items[0].id)
        assert detail is not None
        assert base64.b64decode(detail.raw_request_base64 or "") == b"POST /login HTTP/1.1\r\n\r\n"


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_collection_optimistic_lock(async_engine: AsyncEngine) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant = _seed_tenant_sync(sync_url, "wb-org-lock")
    projects = WorkbenchProjectRepository()
    org = OrganizerRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        proj = await projects.create(s, tenant, _project("app"))
        coll = await org.create_collection(s, tenant, proj.id, OrganizerCollectionCreate(name="c1"))
        assert coll.version == 1

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        updated = await org.update_collection(
            s, tenant, coll.id, OrganizerCollectionUpdate(expected_version=1, name="c1-renamed")
        )
        assert updated.version == 2
        assert updated.name == "c1-renamed"

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        with pytest.raises(OptimisticLockError):
            await org.update_collection(
                s, tenant, coll.id, OrganizerCollectionUpdate(expected_version=1, name="stale")
            )


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_item_search_by_tag_host_and_title(async_engine: AsyncEngine) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant = _seed_tenant_sync(sync_url, "wb-org-search")
    projects = WorkbenchProjectRepository()
    org = OrganizerRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        proj = await projects.create(s, tenant, _project("app"))
        coll = await org.create_collection(s, tenant, proj.id, OrganizerCollectionCreate(name="c1"))
        await org.create_item(
            s,
            tenant,
            coll.id,
            OrganizerItemCreate(
                title="Admin login", host="admin.example.com", tags=("auth", "idor")
            ),
            raw_request=None,
            raw_response=None,
        )
        await org.create_item(
            s,
            tenant,
            coll.id,
            OrganizerItemCreate(title="Search API", host="api.example.com", tags=("xss",)),
            raw_request=None,
            raw_response=None,
        )

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        by_tag, total_tag = await org.list_items(s, tenant, proj.id, tag="idor")
        assert total_tag == 1
        assert by_tag[0].title == "Admin login"

        by_host, total_host = await org.list_items(s, tenant, proj.id, host="api.example.com")
        assert total_host == 1
        assert by_host[0].title == "Search API"

        by_title, total_title = await org.list_items(s, tenant, proj.id, query="login")
        assert total_title == 1
        assert by_title[0].host == "admin.example.com"

        all_items, total_all = await org.list_items(s, tenant, proj.id)
        assert total_all == 2
