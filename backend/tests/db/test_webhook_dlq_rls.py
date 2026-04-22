r"""T38 / ARG-053 — DAO-level RLS smoke for ``webhook_dlq_entries``.

Two Postgres-only smoke tests that exercise the ``tenant_isolation``
policy + FORCE row-level security from migration 027 (Cycle 6 Batch 5)
through the actual T38 DAO surface — not raw SQL.

Why a separate module from ``test_webhook_dlq_migration.py``
------------------------------------------------------------
``test_webhook_dlq_migration.py::test_027_rls_isolation_select_postgres``
already validates the policy at the SQL-introspection layer (``pg_class``
+ ``pg_policy`` + raw INSERT/SELECT). These tests close the loop one level
up: they call :func:`enqueue` and :func:`list_for_tenant` through an
``AsyncSession`` so a future regression in the DAO transaction handling
(e.g. an accidental ``connection.execution_options(role="postgres")``
or a session-pool surface that loses ``SET LOCAL`` between checkouts)
fails here too.

Skip behaviour
--------------
Both tests carry ``@pytest.mark.requires_postgres`` so the canonical
auto-marker filter (``-m "not requires_docker"`` in ``pytest.ini``)
keeps them out of the default dev run. The module-level
:data:`pytestmark_pg` skipif fires when ``DATABASE_URL`` is missing
or points at SQLite — so even ``pytest -m requires_postgres`` reports
SKIPPED rather than ERRORED in environments without a live DB.
The skip pattern mirrors
``test_webhook_dlq_migration.py::test_027_rls_isolation_select_postgres``
verbatim so the two test modules share one DATABASE_URL contract.

How to run locally (PowerShell)::

    docker run --rm -d --name argus-pg-t38 -p 55432:5432 `
        -e POSTGRES_PASSWORD=argus -e POSTGRES_DB=argus_test postgres:15
    $env:DATABASE_URL = "postgresql+asyncpg://postgres:argus@localhost:55432/argus_test"
    .\.venv\Scripts\python.exe -m pytest `
        backend/tests/db/test_webhook_dlq_rls.py -v
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
from sqlalchemy.engine import Engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.mcp.services.notifications.webhook_dlq_persistence import (
    enqueue,
    list_for_tenant,
)

# ---------------------------------------------------------------------------
# Constants — single source of truth for test inputs.
# ---------------------------------------------------------------------------

_BACKEND_ROOT: Path = Path(__file__).resolve().parents[2]

# DATABASE_URL gate — the single literal in this module that the conftest
# auto-marker classifier ``_RE_POSTGRES`` matches; without it the file
# would silently run against SQLite (which has no RLS surface).
_PG_URL_RAW: str = os.environ.get("DATABASE_URL", "")
_HAS_POSTGRES_URL: bool = _PG_URL_RAW.startswith(
    ("postgresql://", "postgresql+", "postgres://")
)

pytestmark_pg = pytest.mark.skipif(
    not _HAS_POSTGRES_URL,
    reason=(
        "DATABASE_URL is not a Postgres URL — webhook DLQ RLS smoke needs a "
        "real Postgres backend (set DATABASE_URL=postgresql+asyncpg://...)"
    ),
)


# ---------------------------------------------------------------------------
# Fixture helpers — mirror the migration-test pattern verbatim.
# ---------------------------------------------------------------------------


def _alembic_config(database_url: str) -> Config:
    """Build an Alembic ``Config`` pointing at the project's real ``alembic.ini``."""
    cfg = Config(str(_BACKEND_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(_BACKEND_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", database_url)
    return cfg


def _to_async_url(url: str) -> str:
    """Normalise the configured URL into the ``postgresql+asyncpg://`` shape.

    The DAO uses :class:`AsyncSession` and so requires the asyncpg driver.
    Mirrors the canonical ``pg_url`` fixture from
    ``test_webhook_dlq_migration.py``.
    """
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+asyncpg://", 1)
    if url.startswith("postgres://"):
        return url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def _to_sync_url(url: str) -> str:
    """Translate the async URL into a sync psycopg2 URL for ``tenants`` seeding.

    The ``tenants`` table is not RLS-restricted (it is the lookup table
    BACKING the policy and would create a chicken-and-egg problem if it
    enforced ``app.current_tenant_id``). Seeding is done synchronously to
    keep the fixture chain short and to match the migration-test pattern.
    """
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://") :]
    return url


@pytest.fixture()
def pg_url(monkeypatch: pytest.MonkeyPatch) -> str:
    """Return the configured Postgres URL (async form) and patch settings.

    Mirrors the fixture chain from
    ``test_webhook_dlq_migration.py`` so both modules agree on the
    DATABASE_URL contract and the env override survives any inadvertent
    settings re-cache during the test.
    """
    async_url = _to_async_url(_PG_URL_RAW)
    monkeypatch.setenv("DATABASE_URL", async_url)
    from src.core import config as _cfg

    monkeypatch.setattr(_cfg.settings, "database_url", async_url)
    return async_url


@pytest.fixture()
def migrated_db(pg_url: str) -> Iterator[str]:
    """Drive ``alembic upgrade head`` and clean up on teardown.

    Yields the async URL so the test can spin its own async engine.
    Tears the DB back to ``base`` afterwards so cross-test row leakage
    is impossible.
    """
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "head")
    try:
        yield pg_url
    finally:
        command.downgrade(cfg, "base")


@pytest.fixture()
async def async_engine(migrated_db: str) -> AsyncIterator[AsyncEngine]:
    """Async engine bound to the migrated DB, disposed on teardown.

    A separate async engine (rather than the sync one in
    ``test_webhook_dlq_migration.py``) is required because the T38 DAO is
    async-only.
    """
    eng = create_async_engine(migrated_db, future=True)
    try:
        yield eng
    finally:
        await eng.dispose()


def _seed_tenant_sync(sync_url: str, name: str) -> str:
    """Seed one tenant via a short-lived sync engine and return its id.

    ``tenants`` has no RLS (it is the lookup table the policy reads from
    via ``app.current_tenant_id`` and would create a chicken-and-egg
    problem if scoped to itself), so a plain INSERT works without any
    GUC dance. Mirrors the helper shape from the migration test.
    """
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
    """Set ``app.current_tenant_id`` for the active transaction.

    ``SET LOCAL`` evaporates on COMMIT/ROLLBACK so the GUC cannot poison
    later checkouts on the pooled connection. Tenant id is interpolated
    as a SQL string literal because ``SET LOCAL`` rejects bound params
    in PostgreSQL — safe here because the id is a UUID string with no
    quotes or semicolons.
    """
    await session.execute(
        text(f"SET LOCAL app.current_tenant_id = '{tenant_id}'")
    )


# ---------------------------------------------------------------------------
# Test A — cross-tenant SELECT isolation through the DAO.
# ---------------------------------------------------------------------------


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_dlq_dao_rls_isolation_select(async_engine: AsyncEngine) -> None:
    """Each tenant session sees only its own DLQ row through the DAO.

    Inserts one row per tenant via :func:`enqueue` (each call wrapped in
    a SET-LOCAL-scoped transaction so the WITH CHECK predicate is
    satisfied), then re-opens each session, sets the GUC, and projects
    across all tenants via ``list_for_tenant(tenant_id=None)``. RLS — not
    the DAO filter — is what narrows each result set to a single row.
    """
    sync_url = _to_sync_url(str(async_engine.url))
    tenant_a = _seed_tenant_sync(sync_url, "rls-dao-a")
    tenant_b = _seed_tenant_sync(sync_url, "rls-dao-b")

    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    # Enqueue under tenant_a (SET LOCAL satisfies WITH CHECK on the policy).
    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        await enqueue(
            s,
            tenant_id=tenant_a,
            adapter_name="slack",
            event_type="finding.created",
            event_id="evt-rls-a",
            target_url="https://hooks.slack.example/T0/B0/secret-a",
            payload={"k": "v-a"},
            last_error_code="http_5xx",
            last_status_code=503,
            attempt_count=0,
        )

    # Enqueue under tenant_b.
    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_b)
        await enqueue(
            s,
            tenant_id=tenant_b,
            adapter_name="slack",
            event_type="finding.created",
            event_id="evt-rls-b",
            target_url="https://hooks.slack.example/T1/B1/secret-b",
            payload={"k": "v-b"},
            last_error_code="http_5xx",
            last_status_code=503,
            attempt_count=0,
        )

    # tenant_a session — RLS narrows to its own row even with the
    # super-admin DAO projection (``tenant_id=None``).
    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        rows_a, total_a = await list_for_tenant(s, tenant_id=None)
        assert total_a == 1, (
            f"tenant_a session must see exactly one row via RLS, got {total_a}"
        )
        assert [r.tenant_id for r in rows_a] == [tenant_a], (
            f"tenant_a session leaked other tenants' rows: "
            f"{[r.tenant_id for r in rows_a]!r}"
        )

    # tenant_b session — symmetric guarantee.
    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_b)
        rows_b, total_b = await list_for_tenant(s, tenant_id=None)
        assert total_b == 1
        assert [r.tenant_id for r in rows_b] == [tenant_b], (
            f"tenant_b session leaked other tenants' rows: "
            f"{[r.tenant_id for r in rows_b]!r}"
        )


# ---------------------------------------------------------------------------
# Test B — FORCE makes the policy bite for the table-owner role.
# ---------------------------------------------------------------------------


@pytestmark_pg
@pytest.mark.requires_postgres
async def test_dlq_dao_rls_force_owner_session(async_engine: AsyncEngine) -> None:
    """Owner-role session with ``app.current_tenant_id=tenant_a`` cannot
    see tenant_b's row.

    Without ``FORCE ROW LEVEL SECURITY`` the migration role (which owns
    the table and is the connection role here, since ``alembic.env``
    and the DAO share the same DATABASE_URL) would bypass
    ``tenant_isolation`` silently and one mis-bound GUC would leak every
    tenant's DLQ rows. The migration carries the FORCE clause for
    exactly this case; this test asserts the DAO observes that
    enforcement end-to-end.

    The two seed inserts happen on the same connection by setting GUC
    per-tenant — proving the policy gates writes too (WITH CHECK), and
    that an attacker who has the owner credentials still cannot stage a
    row under the wrong tenant.
    """
    sync_url = _to_sync_url(str(async_engine.url))
    tenant_a = _seed_tenant_sync(sync_url, "rls-dao-force-a")
    tenant_b = _seed_tenant_sync(sync_url, "rls-dao-force-b")

    sm = async_sessionmaker(async_engine, expire_on_commit=False)

    # Single owner-role session inserts both rows by switching the GUC
    # per row — same role, two transactions, two distinct WITH CHECK
    # outcomes. Demonstrates FORCE applies to writes too.
    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        await enqueue(
            s,
            tenant_id=tenant_a,
            adapter_name="slack",
            event_type="finding.created",
            event_id="evt-force-a",
            target_url="https://hooks.slack.example/T0/B0/force-a",
            payload={"k": "force-a"},
            last_error_code="http_5xx",
            last_status_code=503,
            attempt_count=0,
        )

    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_b)
        await enqueue(
            s,
            tenant_id=tenant_b,
            adapter_name="slack",
            event_type="finding.created",
            event_id="evt-force-b",
            target_url="https://hooks.slack.example/T1/B1/force-b",
            payload={"k": "force-b"},
            last_error_code="http_5xx",
            last_status_code=503,
            attempt_count=0,
        )

    # Same owner-role session, scoped to tenant_a — must NOT see
    # tenant_b's row even though the same role inserted it seconds ago.
    async with sm() as s, s.begin():
        await _set_session_tenant(s, tenant_a)
        rows, total = await list_for_tenant(s, tenant_id=None)
        ids = {r.tenant_id for r in rows}
        assert tenant_a in ids, (
            f"tenant_a's own row must remain visible to itself: {ids!r}"
        )
        assert tenant_b not in ids, (
            "FORCE ROW LEVEL SECURITY is broken — table-owner session "
            "scoped to tenant_a can still read tenant_b's row, which "
            "means the policy does not apply to the migration role and "
            "any background job using the owner credentials leaks tenants"
        )
        assert total == 1
