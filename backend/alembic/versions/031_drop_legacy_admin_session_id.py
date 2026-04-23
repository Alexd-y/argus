"""Drop legacy admin_sessions.session_id; promote session_token_hash to PK.

Revision ID: 031
Revises: 030
Create Date: 2026-04-23

ARG-062 / Cycle 7 / C7-T07 / ISS-T20-003 Phase 2c — destructive cleanup of the
030 → 031 grace window. Migration 030 introduced
``session_token_hash = HMAC-SHA256(ADMIN_SESSION_PEPPER, raw_token)`` as the
primary at-rest identifier and kept the legacy raw ``session_id`` column NULL-
able for one TTL window so live cookies issued before the deploy kept working
through the in-resolver fallback. This migration closes that window:

    1. Backfill any straggler ``session_token_hash IS NULL`` rows when the
       pepper is configured (defensive — 030 already did the bulk pass, but
       a row inserted between 030 and 031 with the legacy flag on is still
       possible in mixed-deploy windows).
    2. Tombstone any row that *still* has ``session_token_hash IS NULL``
       (pepper unset → unreachable from the hash path, would become
       orphaned by the column drop). ``revoked_at = now()`` keeps the audit
       trail and lets the daily janitor expire them.
    3. Promote ``session_token_hash`` to ``NOT NULL`` and rebuild the table
       with ``session_token_hash`` as the sole PRIMARY KEY (the old
       ``ix_admin_sessions_token_hash`` UNIQUE INDEX from 030 is folded
       into the PK on rebuild — having both is redundant and would fail
       ``CREATE TABLE`` on a fresh DB).
    4. Drop the legacy ``session_id`` column.

Pre-flight signals (operator MUST verify before applying in production —
see ``docs/operations/admin-sessions.md`` §"Pre-flight gate for Alembic 031"):

    - ``count(*) where session_token_hash IS NULL`` is 0 (or only acceptable
      stragglers — see runbook).
    - 24 h have elapsed since 030 deploy (≥ 2 × ADMIN_SESSION_TTL).
    - ``ADMIN_SESSION_LEGACY_RAW_WRITE`` and ``ADMIN_SESSION_LEGACY_RAW_FALLBACK``
      have been set to ``false`` for at least one TTL window OR the
      service is rebuilding with C7-T07's flag-removed binary (this
      migration is paired with the binary).

This migration is **forward-only by design**. ``downgrade()`` re-creates the
``session_id`` column + index + PK structure (best-effort: data loss is
unavoidable because raw tokens were never persisted hashed and HMAC is
one-way). Operators should treat downgrade as "schema rollback for a fresh
DB only" — for a populated DB, the practical recovery path is restore-from-
backup. This is documented at the top of the file so a panicked operator
does not run a downgrade expecting their tokens back.

Dialect handling
----------------
SQLite has no ``ALTER COLUMN`` / ``ALTER PRIMARY KEY``; ``batch_alter_table``
emits a copy-rebuild-rename dance under the hood. The Postgres path uses
``alter_column`` + ``ALTER TABLE … DROP CONSTRAINT … / ADD CONSTRAINT …``.
Both paths produce the same end-state schema, asserted in the
``test_031_drop_legacy_admin_session_id_migration`` integration test.

Idempotency
-----------
* Defensive ``sa.inspect`` checks prevent double-drops if the migration is
  re-run after a partial failure.
* Backfill / tombstone steps are SET-WHERE so re-running is a no-op once the
  column already meets the post-031 invariant.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "031"
down_revision: str | None = "030"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

logger = logging.getLogger("alembic.031_drop_legacy_admin_session_id")

ADMIN_SESSIONS_TABLE = "admin_sessions"
LEGACY_COL = "session_id"
HASH_COL = "session_token_hash"
HASH_INDEX = "ix_admin_sessions_token_hash"
PEPPER_ENV = "ADMIN_SESSION_PEPPER"


def _hash_token(pepper: str, raw_token: str) -> str:
    """HMAC-SHA256(pepper, raw_token) hex — must match
    ``src.auth.admin_sessions.hash_session_token`` byte-for-byte so the
    backfill produced here is resolvable post-deploy."""
    return hmac.new(
        pepper.encode("utf-8"),
        raw_token.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _existing_columns(bind: sa.engine.Connection, table: str) -> set[str]:
    inspector = sa.inspect(bind)
    if table not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns(table)}


def _existing_indexes(bind: sa.engine.Connection, table: str) -> set[str]:
    inspector = sa.inspect(bind)
    if table not in inspector.get_table_names():
        return set()
    return {
        name
        for idx in inspector.get_indexes(table)
        if (name := idx.get("name")) is not None
    }


def _backfill_stragglers(bind: sa.engine.Connection) -> int:
    """Hash any row still missing ``session_token_hash`` when the pepper is set.

    030 ran the bulk backfill, but a deploy that sat in the grace window
    with ``ADMIN_SESSION_LEGACY_RAW_WRITE=true`` could have minted rows
    that landed on a Postgres replica between 030 and 031. We re-hash any
    row whose ``session_id`` is still present. Returns the row count
    actually updated — emitted in the operator log so a non-zero number
    is visible at deploy-time.

    Idempotent: returns 0 if ``session_id`` has already been dropped (a
    repeated upgrade or a fresh-schema deployment that never had the
    legacy column).
    """
    pepper = os.getenv(PEPPER_ENV, "").strip()
    if not pepper:
        return 0

    columns = _existing_columns(bind, ADMIN_SESSIONS_TABLE)
    if LEGACY_COL not in columns or HASH_COL not in columns:
        return 0

    table = sa.table(
        ADMIN_SESSIONS_TABLE,
        sa.column(LEGACY_COL, sa.String(64)),
        sa.column(HASH_COL, sa.String(64)),
    )
    rows = bind.execute(
        sa.select(table.c.session_id).where(
            sa.and_(table.c.session_id.isnot(None), table.c.session_token_hash.is_(None))
        )
    ).fetchall()

    backfilled = 0
    for (raw_token,) in rows:
        if not raw_token:
            continue
        digest = _hash_token(pepper, raw_token)
        bind.execute(
            sa.update(table)
            .where(table.c.session_id == raw_token)
            .values({HASH_COL: digest})
        )
        backfilled += 1
    return backfilled


def _tombstone_unreachable(bind: sa.engine.Connection) -> int:
    """Mark every still-NULL-hash row as revoked so the PK promotion is safe.

    A row that has ``session_token_hash IS NULL`` after the straggler
    backfill (pepper unset, or the legacy ``session_id`` was already NULL)
    cannot be authenticated post-031 anyway — its bearer token is unknown
    server-side. Tombstoning before the column drop preserves the audit
    trail and lets the daily janitor expire the row on its normal
    schedule. Idempotent: returns 0 if ``session_token_hash`` has already
    been promoted to NOT NULL (no NULL rows can exist).
    """
    columns = _existing_columns(bind, ADMIN_SESSIONS_TABLE)
    if HASH_COL not in columns:
        return 0
    table = sa.table(
        ADMIN_SESSIONS_TABLE,
        sa.column(HASH_COL, sa.String(64)),
        sa.column("revoked_at", sa.DateTime(timezone=True)),
    )
    result = bind.execute(
        sa.update(table)
        .where(
            sa.and_(table.c.session_token_hash.is_(None), table.c.revoked_at.is_(None))
        )
        .values(revoked_at=sa.func.now())
    )
    return result.rowcount or 0


def _delete_unreachable(bind: sa.engine.Connection) -> int:
    """After tombstoning, hard-delete the rows so the PK promotion succeeds.

    A column promoted to PRIMARY KEY must be ``NOT NULL`` for every row.
    Tombstoning sets ``revoked_at``, but ``session_token_hash`` is still
    NULL — those rows have to leave the table. They are unauthenticatable
    (no hash → no resolve) and already revoked, so removing them is the
    only path that keeps the schema invariant. We log the count so an
    operator can correlate any post-deploy logout complaints. Idempotent:
    returns 0 if the column has already been promoted to NOT NULL.
    """
    columns = _existing_columns(bind, ADMIN_SESSIONS_TABLE)
    if HASH_COL not in columns:
        return 0
    table = sa.table(ADMIN_SESSIONS_TABLE, sa.column(HASH_COL, sa.String(64)))
    result = bind.execute(
        sa.delete(table).where(table.c.session_token_hash.is_(None))
    )
    return result.rowcount or 0


def upgrade() -> None:
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"
    is_postgres = bind.dialect.name == "postgresql"

    sessions_existing = _existing_columns(bind, ADMIN_SESSIONS_TABLE)
    if not sessions_existing:
        logger.warning(
            "031_drop_legacy_admin_session_id: %s table missing — nothing to "
            "do. Run migrations 028..030 first.",
            ADMIN_SESSIONS_TABLE,
        )
        return

    if HASH_COL not in sessions_existing:
        raise RuntimeError(
            "031_drop_legacy_admin_session_id: column "
            f"{ADMIN_SESSIONS_TABLE}.{HASH_COL} missing. Apply migration 030 "
            "before 031."
        )

    # Post-state detection — `session_id` is gone AND `session_token_hash`
    # is the sole PK already. This is the shape we'd land on after a
    # successful first run; re-running the SQL would duplicate the PK
    # constraint or trip Postgres into an error. Treat as no-op.
    if LEGACY_COL not in sessions_existing:
        inspector = sa.inspect(bind)
        pk_constraint = inspector.get_pk_constraint(ADMIN_SESSIONS_TABLE)
        pk_cols = set(pk_constraint.get("constrained_columns") or [])
        if pk_cols == {HASH_COL}:
            logger.info(
                "031_drop_legacy_admin_session_id: already applied (PK is "
                "%s, %s column absent) — skipping idempotently.",
                HASH_COL,
                LEGACY_COL,
            )
            return

    backfilled = _backfill_stragglers(bind)
    if backfilled:
        logger.info(
            "031_drop_legacy_admin_session_id: backfilled %d straggler "
            "session_token_hash rows from session_id (pepper-keyed HMAC)",
            backfilled,
        )

    tombstoned = _tombstone_unreachable(bind)
    if tombstoned:
        logger.warning(
            "031_drop_legacy_admin_session_id: tombstoned %d session row(s) "
            "with NULL session_token_hash (unreachable post-deploy). "
            "Affected operators must re-login.",
            tombstoned,
        )
    purged = _delete_unreachable(bind)
    if purged:
        logger.warning(
            "031_drop_legacy_admin_session_id: deleted %d unreachable "
            "session row(s) so session_token_hash can become NOT NULL PK",
            purged,
        )

    indexes_before = _existing_indexes(bind, ADMIN_SESSIONS_TABLE)

    if is_sqlite:
        # SQLite cannot ALTER PRIMARY KEY in place; batch_alter_table emits
        # the copy-rebuild-rename dance. Drop the redundant unique index on
        # session_token_hash *first* (it would collide with the PK on the
        # rebuilt table) and the legacy column in the same batch.
        with op.batch_alter_table(ADMIN_SESSIONS_TABLE) as batch:
            if HASH_INDEX in indexes_before:
                batch.drop_index(HASH_INDEX)
            batch.alter_column(HASH_COL, existing_type=sa.String(64), nullable=False)
            if LEGACY_COL in sessions_existing:
                batch.drop_column(LEGACY_COL)
            batch.create_primary_key("pk_admin_sessions", [HASH_COL])
    else:
        if HASH_INDEX in indexes_before:
            op.drop_index(HASH_INDEX, table_name=ADMIN_SESSIONS_TABLE)
        op.alter_column(
            ADMIN_SESSIONS_TABLE,
            HASH_COL,
            existing_type=sa.String(64),
            nullable=False,
        )
        if is_postgres:
            op.execute(
                f"ALTER TABLE {ADMIN_SESSIONS_TABLE} "
                "DROP CONSTRAINT IF EXISTS admin_sessions_pkey"
            )
        if LEGACY_COL in sessions_existing:
            op.drop_column(ADMIN_SESSIONS_TABLE, LEGACY_COL)
        op.create_primary_key(
            "pk_admin_sessions", ADMIN_SESSIONS_TABLE, [HASH_COL]
        )

    logger.info(
        "031_drop_legacy_admin_session_id: applied (dialect=%s) — session_id "
        "dropped, session_token_hash promoted to NOT NULL PK",
        bind.dialect.name,
    )


def downgrade() -> None:
    """Re-add the ``session_id`` column and restore it as PRIMARY KEY.

    Best-effort schema rollback: the raw tokens are gone (HMAC is one-way),
    so the restored ``session_id`` column is populated from
    ``session_token_hash`` as a placeholder so the NOT-NULL PK constraint
    is satisfiable. This is **NOT** a data rollback — surviving operators
    must re-login. For a populated production DB the practical recovery
    path is restore-from-backup, NOT this downgrade. The placeholder
    population exists only so a fresh-DB rollback (CI / staging reset)
    keeps the migration chain reversible.
    """
    bind = op.get_bind()
    is_sqlite = bind.dialect.name == "sqlite"
    is_postgres = bind.dialect.name == "postgresql"

    sessions_existing = _existing_columns(bind, ADMIN_SESSIONS_TABLE)
    if not sessions_existing:
        return

    if is_sqlite:
        with op.batch_alter_table(ADMIN_SESSIONS_TABLE) as batch:
            if LEGACY_COL not in sessions_existing:
                batch.add_column(
                    sa.Column(LEGACY_COL, sa.String(64), nullable=True)
                )
            batch.alter_column(HASH_COL, existing_type=sa.String(64), nullable=True)
        # Populate session_id placeholder, then re-create the legacy PK
        # structure (PK on session_id + UNIQUE index on session_token_hash).
        op.execute(
            f"UPDATE {ADMIN_SESSIONS_TABLE} "
            f"SET {LEGACY_COL} = {HASH_COL} "
            f"WHERE {LEGACY_COL} IS NULL"
        )
        with op.batch_alter_table(ADMIN_SESSIONS_TABLE) as batch:
            batch.alter_column(LEGACY_COL, existing_type=sa.String(64), nullable=False)
            batch.create_primary_key("pk_admin_sessions", [LEGACY_COL])
            batch.create_index(HASH_INDEX, [HASH_COL], unique=True)
    else:
        if LEGACY_COL not in sessions_existing:
            op.add_column(
                ADMIN_SESSIONS_TABLE,
                sa.Column(LEGACY_COL, sa.String(64), nullable=True),
            )
        op.execute(
            f"UPDATE {ADMIN_SESSIONS_TABLE} "
            f"SET {LEGACY_COL} = {HASH_COL} "
            f"WHERE {LEGACY_COL} IS NULL"
        )
        op.alter_column(
            ADMIN_SESSIONS_TABLE,
            LEGACY_COL,
            existing_type=sa.String(64),
            nullable=False,
        )
        op.alter_column(
            ADMIN_SESSIONS_TABLE,
            HASH_COL,
            existing_type=sa.String(64),
            nullable=True,
        )
        if is_postgres:
            op.execute(
                f"ALTER TABLE {ADMIN_SESSIONS_TABLE} "
                "DROP CONSTRAINT IF EXISTS pk_admin_sessions"
            )
        op.create_primary_key(
            "pk_admin_sessions", ADMIN_SESSIONS_TABLE, [LEGACY_COL]
        )
        op.create_index(
            HASH_INDEX, ADMIN_SESSIONS_TABLE, [HASH_COL], unique=True
        )

    logger.info(
        "031_drop_legacy_admin_session_id: downgraded (dialect=%s) — "
        "session_id restored as PK; session_token_hash demoted to nullable "
        "with UNIQUE index. Surviving operators must re-login.",
        bind.dialect.name,
    )
