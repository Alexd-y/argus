r"""WB-P2a-2 — Postgres RLS + repository integration for proxy tables.

Drives :class:`ProxyRepository` through ``AsyncSession`` with
``SET LOCAL app.current_tenant_id`` and asserts migration-046 ``tenant_isolation``
FORCE policy isolates ``wb_proxy_listeners`` / ``wb_traffic_messages`` /
``wb_traffic_body_artifacts`` across tenants (raw cross-tenant ``count(*)``
proves RLS, not just the DAO filter). Also covers listener optimistic locking
and body persistence (inline round-trip).

Skip behaviour mirrors ``tests/db/test_webhook_dlq_rls.py``.

Run locally (PowerShell)::

    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/web_workbench/test_proxy_rls.py -v
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

from cryptography.fernet import Fernet

from src.web_workbench.contracts.project import WorkbenchProjectCreate
from src.web_workbench.contracts.proxy import ProxyListenerCreate, ProxyListenerUpdate
from src.web_workbench.projects.repository import WorkbenchProjectRepository
from src.web_workbench.proxy.body_store import InMemoryBodyObjectStore
from src.web_workbench.proxy.ca_lifecycle import (
    FernetSecretSealer,
    issue_ca,
    load_ca,
)
from src.web_workbench.proxy.repository import (
    CaptureInput,
    OptimisticLockError,
    ProxyRepository,
)
from src.policy.scope import ScopeKind, ScopeRule

_BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]

_PG_URL_RAW: str = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL: bool = _PG_URL_RAW.startswith(("postgresql://", "postgresql+", "postgres://"))

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason="DATABASE_URL is not a Postgres URL — WB proxy RLS needs Postgres",
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


def _capture() -> CaptureInput:
    return CaptureInput(
        method="POST",
        scheme="https",
        host="app.example.com",
        port=443,
        path="/submit",
        http_version="HTTP/1.1",
        forward_outcome="forward",
        in_scope=True,
        status_code=200,
        request_headers=(("Host", "app.example.com"),),
        response_headers=(("Content-Type", "application/json"),),
        request_body=b'{"a":1}',
        response_body=b'{"ok":true}',
        request_content_type="application/json",
        response_content_type="application/json",
    )


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_proxy_cross_tenant_isolation(async_engine: AsyncEngine) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant_a = _seed_tenant_sync(sync_url, "wb-proxy-a")
    tenant_b = _seed_tenant_sync(sync_url, "wb-proxy-b")
    projects = WorkbenchProjectRepository()
    proxy = ProxyRepository()
    store = InMemoryBodyObjectStore()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        proj_a = await projects.create(s, tenant_a, _project("app-a"))
        await proxy.create_listener(s, tenant_a, proj_a.id, ProxyListenerCreate(name="edge"))
        await proxy.persist_message(s, tenant_a, proj_a.id, _capture(), object_store=store)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_b)
        proj_b = await projects.create(s, tenant_b, _project("app-b"))
        await proxy.create_listener(s, tenant_b, proj_b.id, ProxyListenerCreate(name="edge"))
        # tenant_b sees none of tenant_a's traffic (RLS, raw count).
        items, total = await proxy.list_history(s, tenant_b, proj_b.id)
        assert total == 0
        assert items == []
        raw_msgs = await s.execute(text("SELECT count(*) FROM wb_traffic_messages"))
        assert raw_msgs.scalar_one() == 0
        raw_listeners = await s.execute(text("SELECT count(*) FROM wb_proxy_listeners"))
        assert raw_listeners.scalar_one() == 1  # only tenant_b's own listener

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        items, total = await proxy.list_history(s, tenant_a, proj_a.id)
        assert total == 1
        msg = items[0]
        assert msg.request_body is not None
        assert msg.request_body.storage_backend == "inline"
        assert msg.response_body is not None
        raw_bodies = await s.execute(text("SELECT count(*) FROM wb_traffic_body_artifacts"))
        assert raw_bodies.scalar_one() == 2


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_listener_optimistic_lock(async_engine: AsyncEngine) -> None:
    sync_url = _to_sync_url(str(async_engine.url))
    tenant = _seed_tenant_sync(sync_url, "wb-proxy-lock")
    projects = WorkbenchProjectRepository()
    proxy = ProxyRepository()
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        proj = await projects.create(s, tenant, _project("app"))
        listener = await proxy.create_listener(s, tenant, proj.id, ProxyListenerCreate(name="edge"))
        assert listener.version == 1

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        updated = await proxy.update_listener(
            s,
            tenant,
            listener.id,
            ProxyListenerUpdate(expected_version=1, status="active"),
        )
        assert updated.version == 2
        assert updated.status.value == "active"

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        with pytest.raises(OptimisticLockError):
            await proxy.update_listener(
                s,
                tenant,
                listener.id,
                ProxyListenerUpdate(expected_version=1, status="disabled"),
            )


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_listener_ca_issue_persists_sealed_and_reloads(
    async_engine: AsyncEngine,
) -> None:
    """Issue a CA → only sealed key persisted → reload from DB signs a leaf."""
    sync_url = _to_sync_url(str(async_engine.url))
    tenant = _seed_tenant_sync(sync_url, "wb-proxy-ca")
    projects = WorkbenchProjectRepository()
    proxy = ProxyRepository()
    sealer = FernetSecretSealer(Fernet.generate_key())
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        proj = await projects.create(s, tenant, _project("app"))
        listener = await proxy.create_listener(s, tenant, proj.id, ProxyListenerCreate(name="edge"))
        sealed = issue_ca(sealer, common_name="Integration CA")
        dto = await proxy.set_listener_ca(
            s, tenant, listener.id, sealed, expected_version=listener.version
        )
        assert dto.version == listener.version + 1
        assert dto.ca is not None
        assert dto.ca.fingerprint_sha256 == sealed.fingerprint_sha256

    # The DB stores ciphertext only — never the plaintext private key.
    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant)
        row = (
            await s.execute(
                text(
                    "SELECT ca_cert_pem, ca_sealed_key, ca_secrets_ref "
                    "FROM wb_proxy_listeners WHERE id = :id"
                ),
                {"id": listener.id},
            )
        ).one()
        cert_pem, sealed_key, secrets_ref = row
        assert secrets_ref == "env:WB_CA_SEALING_KEY"
        assert b"PRIVATE KEY" not in bytes(sealed_key)

        ca = load_ca(sealer, certificate_pem=cert_pem, sealed_key=bytes(sealed_key))
        leaf = ca.issue_leaf("app.example.com")
        assert b"BEGIN CERTIFICATE" in leaf.certificate_pem
