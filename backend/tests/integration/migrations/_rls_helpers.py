"""Exercise Row Level Security under a NON-superuser role.

PostgreSQL superusers (and, without ``FORCE RLS``, table owners) BYPASS row
level security. The local/validation Postgres connects as ``argus`` — a
superuser — so RLS *isolation* assertions run against it would spuriously see
every tenant's rows. Production connects as a limited application role; these
helpers reproduce that by:

1. creating a dedicated ``NOSUPERUSER`` role (idempotent), and granting it the
   table/sequence privileges the app role has, then
2. switching the current transaction to that role via ``SET LOCAL ROLE`` so RLS
   is actually enforced for the remainder of the transaction.

This does NOT weaken any assertion — it makes the RLS policies observable at
all, which is the whole point of the test. Seed/setup work stays on the
superuser connection; only the isolation/​WITH-CHECK assertions assume the
restricted role.
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

RLS_TEST_ROLE = "argus_rls_app"

_CREATE_ROLE_SQL = f"""
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{RLS_TEST_ROLE}') THEN
        CREATE ROLE {RLS_TEST_ROLE} NOSUPERUSER NOINHERIT;
    END IF;
END
$$;
"""

_GRANT_SQL = (
    f"GRANT USAGE ON SCHEMA public TO {RLS_TEST_ROLE}",
    f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO {RLS_TEST_ROLE}",
    f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO {RLS_TEST_ROLE}",
)


def _to_sync_url(url: str) -> str:
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if url.startswith(prefix):
            return "postgresql://" + url[len(prefix) :]
    if url.startswith("postgres://"):
        return "postgresql://" + url[len("postgres://") :]
    return url


def ensure_rls_role(database_url: str) -> None:
    """Create the NOSUPERUSER role and (re)grant it access to public tables.

    Idempotent — safe to call after every ``upgrade head`` (grants must be
    re-applied because each test rebuilds the schema). Uses a committed
    AUTOCOMMIT sync connection (superuser) so the role/grants persist past the
    caller's transaction.
    """
    engine = sa.create_engine(
        _to_sync_url(database_url), future=True, isolation_level="AUTOCOMMIT"
    )
    try:
        with engine.connect() as conn:
            conn.execute(text(_CREATE_ROLE_SQL))
            for stmt in _GRANT_SQL:
                conn.execute(text(stmt))
    finally:
        engine.dispose()


async def assume_rls_role(session: AsyncSession) -> None:
    """Drop to the NOSUPERUSER role for the rest of this transaction (async)."""
    await session.execute(text(f"SET LOCAL ROLE {RLS_TEST_ROLE}"))


def assume_rls_role_sync(conn: sa.Connection) -> None:
    """Drop to the NOSUPERUSER role for the rest of this transaction (sync)."""
    conn.execute(text(f"SET LOCAL ROLE {RLS_TEST_ROLE}"))
