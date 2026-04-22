"""Admin MFA columns — TOTP secret + backup codes + session mfa_passed_at.

Revision ID: 032
Revises: 030
Create Date: 2026-04-22

ARG-062 / Cycle 7 / C7-T01 / ISS-T20-003 Phase 2a Option 1.

Adds backend-managed TOTP MFA columns to the existing ``admin_users`` table
(introduced in Alembic 028) and adds ``mfa_passed_at`` to ``admin_sessions``
so the resolver can enforce a re-auth window for super-admin endpoints.

Schema (per ``ai_docs/develop/issues/ISS-T20-003-phase2.md`` §Phase 2a):

    admin_users.mfa_enabled            BOOL DEFAULT FALSE NOT NULL
    admin_users.mfa_secret_encrypted   BYTEA NULLABLE       -- Fernet ciphertext
    admin_users.mfa_backup_codes_hash  TEXT[] NULLABLE      -- bcrypt hashes
    admin_sessions.mfa_passed_at       TIMESTAMPTZ NULLABLE -- when 2FA accepted

Backwards-compat: existing rows get ``mfa_enabled = FALSE`` and the three new
nullable columns default to ``NULL``. Super-admin enforcement happens in
application code (``Settings.admin_mfa_enforce_roles``), not at the DB layer
— operators can roll out MFA gradually without a schema redeploy.

Sequencing note (down_revision)
-------------------------------
The C7 plan sketch says ``Revises: 031`` but Cycle 7 task ``C7-T07`` (which
creates the ``031_drop_legacy_admin_session_id`` migration) is scheduled for
a later wave. Keeping ``032 → 030`` here is the only correct chain on
``main`` today; ``C7-T07`` will rebase ``032`` to ``Revises: 031`` once
``031`` lands. This avoids shipping a broken migration head.

Idempotency
-----------
All ``add_column`` / ``drop_column`` operations check the live schema via
``sa.inspect`` first, so re-running ``alembic upgrade`` (or replaying after
a partial failure) is safe on both Postgres and SQLite. The downgrade is
symmetrical and tolerates already-dropped columns.

Dialect handling
----------------
* Postgres native types: ``BOOLEAN``, ``BYTEA``, ``TEXT[]``, ``TIMESTAMPTZ``.
* SQLite (test/dev only) uses ``BOOLEAN`` (TINYINT under the hood),
  ``BLOB``, ``JSON`` (ARRAY is unsupported), and ``DATETIME``. Schema-add
  operations on SQLite require ``batch_alter_table`` because the SQLite
  ``ALTER TABLE ADD COLUMN`` cannot apply ``NOT NULL`` with a server
  default in a single statement on older versions — we use
  ``batch_alter_table`` to stay compatible with the test matrix.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "032"
down_revision: str | None = "030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

logger = logging.getLogger("alembic.032_admin_mfa_columns")

ADMIN_USERS_TABLE = "admin_users"
ADMIN_SESSIONS_TABLE = "admin_sessions"

COL_MFA_ENABLED = "mfa_enabled"
COL_MFA_SECRET_ENCRYPTED = "mfa_secret_encrypted"
COL_MFA_BACKUP_CODES_HASH = "mfa_backup_codes_hash"
COL_MFA_PASSED_AT = "mfa_passed_at"


def _existing_columns(bind: sa.engine.Connection, table: str) -> set[str]:
    """Return the live column names of ``table`` (empty set if missing)."""
    inspector = sa.inspect(bind)
    if table not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns(table)}


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"
    is_postgres = bind.dialect.name == "postgresql"

    users_existing = _existing_columns(bind, ADMIN_USERS_TABLE)
    sessions_existing = _existing_columns(bind, ADMIN_SESSIONS_TABLE)

    if not users_existing:
        logger.warning(
            "032_admin_mfa_columns: %s table missing — skipping admin_users "
            "MFA columns. Run migrations 028..030 first.",
            ADMIN_USERS_TABLE,
        )
    else:
        # Compose dialect-aware column definitions once so the SQLite
        # batch path and the Postgres path stay byte-equivalent. The
        # ``Any`` typing is intentional — ``ARRAY[str]`` and ``LargeBinary``
        # share no concrete subtype mypy can unify, but both satisfy
        # :class:`sqlalchemy.types.TypeEngine` at runtime.
        backup_codes_type: sa.types.TypeEngine[Any]
        secret_type: sa.types.TypeEngine[Any]
        if is_postgres:
            backup_codes_type = postgresql.ARRAY(sa.Text())
            secret_type = postgresql.BYTEA()
        else:
            backup_codes_type = sa.JSON()
            secret_type = sa.LargeBinary()

        new_user_columns: list[sa.Column[Any]] = []
        if COL_MFA_ENABLED not in users_existing:
            new_user_columns.append(
                sa.Column(
                    COL_MFA_ENABLED,
                    sa.Boolean(),
                    nullable=False,
                    server_default=sa.text("false") if is_postgres else sa.text("0"),
                )
            )
        if COL_MFA_SECRET_ENCRYPTED not in users_existing:
            new_user_columns.append(
                sa.Column(COL_MFA_SECRET_ENCRYPTED, secret_type, nullable=True)
            )
        if COL_MFA_BACKUP_CODES_HASH not in users_existing:
            new_user_columns.append(
                sa.Column(COL_MFA_BACKUP_CODES_HASH, backup_codes_type, nullable=True)
            )

        if new_user_columns:
            if is_sqlite:
                with op.batch_alter_table(ADMIN_USERS_TABLE) as batch:
                    for column in new_user_columns:
                        batch.add_column(column)
            else:
                for column in new_user_columns:
                    op.add_column(ADMIN_USERS_TABLE, column)

            # ``server_default`` ensures existing rows get ``mfa_enabled = false``
            # at column-add time. Drop the default afterwards on Postgres so the
            # ORM ``default=False`` is the single source of truth going forward;
            # SQLite has no equivalent ALTER, so we leave the default in place
            # (no functional difference — both produce ``mfa_enabled = false``).
            if (
                is_postgres
                and COL_MFA_ENABLED in {c.name for c in new_user_columns}
            ):
                op.alter_column(
                    ADMIN_USERS_TABLE,
                    COL_MFA_ENABLED,
                    server_default=None,
                )

    if not sessions_existing:
        logger.warning(
            "032_admin_mfa_columns: %s table missing — skipping mfa_passed_at. "
            "Run migrations 028..030 first.",
            ADMIN_SESSIONS_TABLE,
        )
    elif COL_MFA_PASSED_AT not in sessions_existing:
        passed_at_column = sa.Column(
            COL_MFA_PASSED_AT,
            sa.DateTime(timezone=True),
            nullable=True,
        )
        if is_sqlite:
            with op.batch_alter_table(ADMIN_SESSIONS_TABLE) as batch:
                batch.add_column(passed_at_column)
        else:
            op.add_column(ADMIN_SESSIONS_TABLE, passed_at_column)

    logger.info(
        "032_admin_mfa_columns: applied (dialect=%s, users_added=%d, "
        "sessions_added=%d)",
        bind.dialect.name,
        sum(
            1
            for c in (
                COL_MFA_ENABLED,
                COL_MFA_SECRET_ENCRYPTED,
                COL_MFA_BACKUP_CODES_HASH,
            )
            if c not in users_existing
        ),
        0 if not sessions_existing or COL_MFA_PASSED_AT in sessions_existing else 1,
    )


def downgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"

    sessions_existing = _existing_columns(bind, ADMIN_SESSIONS_TABLE)
    if COL_MFA_PASSED_AT in sessions_existing:
        if is_sqlite:
            with op.batch_alter_table(ADMIN_SESSIONS_TABLE) as batch:
                batch.drop_column(COL_MFA_PASSED_AT)
        else:
            op.drop_column(ADMIN_SESSIONS_TABLE, COL_MFA_PASSED_AT)

    users_existing = _existing_columns(bind, ADMIN_USERS_TABLE)
    drop_user_cols = [
        col
        for col in (
            COL_MFA_BACKUP_CODES_HASH,
            COL_MFA_SECRET_ENCRYPTED,
            COL_MFA_ENABLED,
        )
        if col in users_existing
    ]
    if drop_user_cols:
        if is_sqlite:
            with op.batch_alter_table(ADMIN_USERS_TABLE) as batch:
                for col in drop_user_cols:
                    batch.drop_column(col)
        else:
            for col in drop_user_cols:
                op.drop_column(ADMIN_USERS_TABLE, col)
