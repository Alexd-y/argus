r"""SEC-002 — FORCE RLS on ``users`` must not break login (migrations 052 + 053).

Proves the migration-053 ``users_auth_bootstrap`` policy lets the pre-auth login
lookup read ``users`` under ``FORCE ROW LEVEL SECURITY`` (052), while keeping
per-tenant isolation for tenant-scoped sessions and strict tenant binding on
writes.

The scenarios mirror the real code paths:

* ``auth.py`` login runs ``SELECT ... FROM users WHERE email = ...`` on a session
  that never sets ``app.current_tenant_id`` — must return the row.
* an authenticated main-API request resolves a tenant (SEC-001), sets the GUC via
  ``set_session_tenant``, and must only see its own tenant's users.
* there is no runtime path that writes ``users`` without a tenant context, and the
  bootstrap policy must not create one — writes must still fail ``WITH CHECK``
  when the tenant does not match (or is unset).

Run locally (PowerShell)::

    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/integration/migrations/test_053_force_rls_login.py -v
"""

from __future__ import annotations

import os
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest
import sqlalchemy.exc as sa_exc
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from tests.integration.migrations._rls_helpers import assume_rls_role, ensure_rls_role

_BACKEND_ROOT: Path = Path(__file__).resolve().parents[3]

_PG_URL_RAW: str = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL: bool = _PG_URL_RAW.startswith(("postgresql://", "postgresql+", "postgres://"))

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason="DATABASE_URL is not a Postgres URL — FORCE RLS needs Postgres",
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
    # RLS isolation must be asserted under a NON-superuser role (the local
    # ``argus`` connection is a superuser and bypasses RLS). Provision it once
    # the schema exists; the isolation tests SET LOCAL ROLE to it.
    ensure_rls_role(pg_url)
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


async def _set_tenant(session: AsyncSession, tenant_id: str) -> None:
    # SET LOCAL does not accept bound parameters; tenant_id is a test-controlled UUID.
    uuid.UUID(tenant_id)
    await session.execute(text(f"SET LOCAL app.current_tenant_id = '{tenant_id}'"))


async def _seed_tenant(session: AsyncSession, name: str) -> str:
    tid = str(uuid.uuid4())
    # ``tenants`` is not in the 052 FORCE set — insertable without a tenant context.
    await session.execute(
        text("INSERT INTO tenants (id, name) VALUES (:id, :name)"),
        {"id": tid, "name": name},
    )
    return tid


async def _seed_user(session: AsyncSession, tenant_id: str, email: str) -> str:
    uid = str(uuid.uuid4())
    await _set_tenant(session, tenant_id)
    await session.execute(
        text(
            "INSERT INTO users (id, tenant_id, email, password_hash, is_active) "
            "VALUES (:id, :tid, :email, :ph, true)"
        ),
        {"id": uid, "tid": tenant_id, "email": email, "ph": "$2b$12$" + "x" * 53},
    )
    return uid


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_force_rls_and_bootstrap_policy_present(async_engine: AsyncEngine) -> None:
    """052 forced ``users`` and 053 installed the bootstrap SELECT policy."""
    async with async_engine.connect() as conn:
        forced = await conn.execute(
            text(
                "SELECT c.relforcerowsecurity FROM pg_class c "
                "JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = current_schema() AND c.relname = 'users'"
            )
        )
        assert forced.scalar_one() is True

        policy = await conn.execute(
            text(
                "SELECT count(*) FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid "
                "WHERE c.relname = 'users' AND p.polname = 'users_auth_bootstrap'"
            )
        )
        assert policy.scalar_one() == 1


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_login_lookup_succeeds_without_tenant_context(async_engine: AsyncEngine) -> None:
    """The pre-auth login query (no GUC) still finds the user under FORCE RLS."""
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        tenant_a = await _seed_tenant(s, "force-rls-a")
        tenant_b = await _seed_tenant(s, "force-rls-b")
        await _seed_user(s, tenant_a, "a@example.com")
        await _seed_user(s, tenant_b, "b@example.com")

    # Fresh session, no ``set_session_tenant`` — exactly what auth.py does.
    async with sm() as s, s.begin():
        row = (
            await s.execute(
                text(
                    "SELECT tenant_id FROM users "
                    "WHERE email = :e AND is_active = true"
                ),
                {"e": "a@example.com"},
            )
        ).first()
        assert row is not None, "login lookup returned no row under FORCE RLS"
        assert row[0] == tenant_a

        total = await s.execute(text("SELECT count(*) FROM users"))
        assert total.scalar_one() == 2, "bootstrap policy should expose all users pre-auth"


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_tenant_scoped_session_is_isolated(async_engine: AsyncEngine) -> None:
    """A session with a tenant GUC set only sees its own tenant's users."""
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        tenant_a = await _seed_tenant(s, "iso-a")
        tenant_b = await _seed_tenant(s, "iso-b")
        await _seed_user(s, tenant_a, "iso-a@example.com")
        await _seed_user(s, tenant_b, "iso-b@example.com")

    async with sm() as s, s.begin():
        await assume_rls_role(s)  # enforce RLS (superuser would bypass it)
        await _set_tenant(s, tenant_a)
        count = await s.execute(text("SELECT count(*) FROM users"))
        assert count.scalar_one() == 1, "tenant A must not see tenant B users"

        cross = await s.execute(
            text("SELECT count(*) FROM users WHERE email = :e"),
            {"e": "iso-b@example.com"},
        )
        assert cross.scalar_one() == 0, "cross-tenant user must be invisible with GUC set"


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_write_still_requires_matching_tenant(async_engine: AsyncEngine) -> None:
    """The read-only bootstrap policy must not loosen INSERT WITH CHECK."""
    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    async with sm() as s, s.begin():
        tenant_a = await _seed_tenant(s, "write-a")
        tenant_b = await _seed_tenant(s, "write-b")

    # Wrong-tenant write: GUC=A, row tenant=B → WITH CHECK violation.
    async with sm() as s, s.begin():
        await assume_rls_role(s)  # enforce RLS WITH CHECK (superuser bypasses)
        await _set_tenant(s, tenant_a)
        with pytest.raises(sa_exc.DBAPIError):
            await s.execute(
                text(
                    "INSERT INTO users (id, tenant_id, email, password_hash, is_active) "
                    "VALUES (:id, :tid, :email, :ph, true)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tid": tenant_b,
                    "email": "evil@example.com",
                    "ph": "$2b$12$" + "x" * 53,
                },
            )

    # No-context write: GUC unset → WITH CHECK on tenant_isolation still fails.
    async with sm() as s, s.begin():
        await assume_rls_role(s)  # enforce RLS WITH CHECK (superuser bypasses)
        with pytest.raises(sa_exc.DBAPIError):
            await s.execute(
                text(
                    "INSERT INTO users (id, tenant_id, email, password_hash, is_active) "
                    "VALUES (:id, :tid, :email, :ph, true)"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tid": tenant_a,
                    "email": "nocontext@example.com",
                    "ph": "$2b$12$" + "x" * 53,
                },
            )
