"""ISS-T20-003 hardening — hash admin session IDs at rest.

Revision ID: 030
Revises: 029
Create Date: 2026-04-22

Closes the 🔴 critical follow-up flagged on B6-T08 review: ``admin_sessions``
stored the raw CSPRNG token in the primary key column, so a database dump,
backup leak, or read-only SQLi turned every active session into a replayable
bearer token.

This migration introduces an at-rest hash:

    session_token_hash = HMAC-SHA256(ADMIN_SESSION_PEPPER, raw_token)

(Keyed hash, not the naive ``sha256(pepper || raw)`` construction — HMAC is
length-extension resistant and is the canonical primitive in tooling.)

Lookups are performed by ``session_token_hash``; the raw token never re-enters
the database. The legacy ``session_id`` column is kept NULL-able for one TTL
window (12 h) so live sessions issued before the deploy keep working — see
``backend/src/auth/admin_sessions.py`` for the in-resolver fallback that
opportunistically backfills ``session_token_hash`` on a legacy hit.

Operational notes
-----------------
* ``ADMIN_SESSION_PEPPER`` must be set to ≥32 random bytes before the deploy.
  Generate with ``python -c "import secrets; print(secrets.token_urlsafe(48))"``.
* If the pepper is missing, the migration **does not crash** — every existing
  row gets ``session_token_hash = NULL`` and is therefore unreachable from the
  hash path. Active sessions invalidate after one TTL; cookie-mode keeps
  working as the fail-safe.
* The downgrade is idempotent: drop the index, drop the column.
* A follow-up migration ``031_drop_legacy_admin_session_id.py`` will drop
  ``session_id`` once two TTL windows have elapsed in production.

Why a separate migration
------------------------
Splitting the schema change from the (separately-deployed) raw-write/raw-read
toggle keeps the rollback story simple: a problem at deploy-time is a single
``alembic downgrade`` plus a config flip back to legacy raw writes.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "030"
down_revision: str | None = "029"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

logger = logging.getLogger("alembic.030_hash_admin_session_ids")

ADMIN_SESSIONS_TABLE = "admin_sessions"
HASH_COLUMN = "session_token_hash"
HASH_INDEX = "ix_admin_sessions_token_hash"
PEPPER_ENV = "ADMIN_SESSION_PEPPER"


def _hash_token(pepper: str, raw_token: str) -> str:
    """HMAC-SHA256(pepper, raw_token) hex — must match
    ``src.auth.admin_sessions.hash_session_token`` byte-for-byte so the
    resolver hits the row backfilled here."""
    return hmac.new(
        pepper.encode("utf-8"),
        raw_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _backfill_token_hash(connection: sa.engine.Connection, *, pepper: str) -> int:
    table = sa.table(
        ADMIN_SESSIONS_TABLE,
        sa.column("session_id", sa.String(64)),
        sa.column(HASH_COLUMN, sa.String(64)),
    )
    rows = connection.execute(
        sa.select(table.c.session_id).where(table.c.session_id.isnot(None))
    ).fetchall()
    backfilled = 0
    for (raw_token,) in rows:
        if not raw_token:
            continue
        digest = _hash_token(pepper, raw_token)
        connection.execute(
            sa.update(table)
            .where(table.c.session_id == raw_token)
            .values({HASH_COLUMN: digest})
        )
        backfilled += 1
    return backfilled


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    if is_sqlite:
        with op.batch_alter_table(ADMIN_SESSIONS_TABLE) as batch:
            batch.add_column(sa.Column(HASH_COLUMN, sa.String(64), nullable=True))
    else:
        op.add_column(
            ADMIN_SESSIONS_TABLE,
            sa.Column(HASH_COLUMN, sa.String(64), nullable=True),
        )

    op.create_index(
        HASH_INDEX,
        ADMIN_SESSIONS_TABLE,
        [HASH_COLUMN],
        unique=True,
    )

    pepper = os.getenv(PEPPER_ENV, "")
    if not pepper:
        logger.warning(
            "030_hash_admin_session_ids: %s unset — existing sessions remain "
            "without session_token_hash and will be unreachable from the hash "
            "path. Cookie-mode auth keeps working; live session-mode tokens "
            "invalidate after one TTL.",
            PEPPER_ENV,
        )
        return

    backfilled = _backfill_token_hash(bind, pepper=pepper)
    logger.info(
        "030_hash_admin_session_ids: backfilled %d session_token_hash rows "
        "using ADMIN_SESSION_PEPPER",
        backfilled,
    )


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    is_sqlite = bind.dialect.name == "sqlite"

    if is_postgres:
        op.execute(f"DROP INDEX IF EXISTS {HASH_INDEX}")
    else:
        try:
            op.drop_index(HASH_INDEX, table_name=ADMIN_SESSIONS_TABLE)
        except Exception:
            pass

    if is_sqlite:
        with op.batch_alter_table(ADMIN_SESSIONS_TABLE) as batch:
            batch.drop_column(HASH_COLUMN)
    else:
        op.drop_column(ADMIN_SESSIONS_TABLE, HASH_COLUMN)
