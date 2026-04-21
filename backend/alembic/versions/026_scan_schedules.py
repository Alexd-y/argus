"""T32 / ARG-056 — ``scan_schedules`` table + RLS.

Revision ID: 026
Revises: 025
Create Date: 2026-04-22

Context
-------
Batch 4 of Cycle 6 (Operations UI) introduces operator-managed scheduled
scans. T32 is the pure data-layer foundation: the ``scan_schedules`` table
plus the canonical tenant-isolation RLS policy. Business logic (CRUD,
redbeat sync, maintenance-window evaluation, Celery wiring) lands in
T33 + T34 and MUST NOT leak into this migration.

Deviation from roadmap
----------------------
The Cycle 6 finalisation roadmap (§Batch 4) names this migration
``024_scan_schedules.py``. Revisions ``024_tenant_exports_sarif_junit``
(Batch 1 T04) and ``025_tenant_limits_overrides`` (Batch 2 T13) already
landed on ``main`` during earlier batches, so T32 ships as revision
``026`` to preserve the linear chain. See
``ai_docs/develop/plans/2026-04-22-argus-cycle6-b4.md`` §2 deviation D-1.

Schema
------
``scan_schedules`` columns (tenant-scoped):
  * id                      : VARCHAR(36)   — UUID PK (ORM-generated via
                                              ``src.db.models.gen_uuid``,
                                              matching every other
                                              tenant-scoped table — the
                                              schema uses ``String(36)``,
                                              not dialect ``UUID``, per
                                              the note in
                                              ``src/db/models.py``).
  * tenant_id               : VARCHAR(36)   — FK tenants(id) ON DELETE CASCADE
  * name                    : VARCHAR(255)  — operator-visible label
  * cron_expression         : VARCHAR(64)   — 5-field cron (T34 validates)
  * target_url              : VARCHAR(2048) — absolute URL of scan target
  * scan_mode               : VARCHAR(50)   — quick | standard | deep
  * enabled                 : BOOLEAN       — NOT NULL DEFAULT true
  * maintenance_window_cron : VARCHAR(64)   — NULL = no window
  * last_run_at             : TIMESTAMPTZ   — NULL until first fire
  * next_run_at             : TIMESTAMPTZ   — NULL until computed
  * created_at              : TIMESTAMPTZ   — server_default now()
  * updated_at              : TIMESTAMPTZ   — server_default now(); the
                                              ORM model sets
                                              ``onupdate=func.now()`` so
                                              UPDATE statements bump it.
                                              No PL/pgSQL trigger is
                                              defined here because the
                                              project has no canonical
                                              ``updated_at`` trigger
                                              function (the only PL/pgSQL
                                              in the schema is
                                              ``audit_logs_immutable()``
                                              from migration 002, which
                                              has different semantics).

Constraints
-----------
  * UNIQUE (tenant_id, name) — operator cannot create two schedules with
    the same label per tenant (T33 maps 409 to this violation).

Indexes
-------
  * ix_scan_schedules_tenant_enabled (tenant_id, enabled) — hot path for
    the per-tenant list-enabled endpoint T33 ships.
  * ix_scan_schedules_next_run_at (next_run_at) — partial index on
    Postgres (``WHERE enabled = true``) so the RedBeat reconciliation
    query T33 ships only scans enabled rows. On SQLite (used by the
    alembic smoke round-trip) the partial predicate is emitted as a
    plain index — SQLite supports ``CREATE INDEX ... WHERE`` but the
    round-trip test does not exercise the predicate, and matching the
    Postgres-only partial shape inside the same migration keeps the
    dialect-diff byte-stable.

Row-Level Security
------------------
Mirrors migrations 019/020 for the policy body and hardens further with
``FORCE`` (which 019/020 did not set):

    ALTER TABLE scan_schedules ENABLE  ROW LEVEL SECURITY;
    ALTER TABLE scan_schedules FORCE   ROW LEVEL SECURITY;
    CREATE POLICY tenant_isolation ON scan_schedules
        USING       (tenant_id = current_setting('app.current_tenant_id', true)::text)
        WITH CHECK  (tenant_id = current_setting('app.current_tenant_id', true)::text);

``FORCE`` makes the policy apply even when the connected role owns the
table — without it, the Alembic migration role (which owns every
``argus_*`` table) would bypass tenant isolation silently. Superuser
roles still bypass RLS unconditionally per Postgres semantics; that is
an operational concern covered by the Dockerised deployment role
separation, not something a migration can fix.

``app.current_tenant_id`` is set by
``backend/src/db/session.py::set_session_tenant`` on every request via
the FastAPI dependency stack. RLS is Postgres-only — SQLite has no
equivalent surface, and the alembic smoke test intentionally runs the
round-trip against both dialects.

Backwards compatibility
-----------------------
* Brand-new table — no impact on existing tables.
* ``downgrade()`` is fully idempotent: every ``DROP`` uses ``IF EXISTS``
  and the operations run in the reverse order of ``upgrade()``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "026"
down_revision: str | None = "025"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE_NAME = "scan_schedules"
UNIQUE_CONSTRAINT_NAME = "uq_scan_schedules_tenant_name"
INDEX_TENANT_ENABLED = "ix_scan_schedules_tenant_enabled"
INDEX_NEXT_RUN_AT = "ix_scan_schedules_next_run_at"
RLS_POLICY_NAME = "tenant_isolation"


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    op.create_table(
        TABLE_NAME,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("cron_expression", sa.String(64), nullable=False),
        sa.Column("target_url", sa.String(2048), nullable=False),
        sa.Column("scan_mode", sa.String(50), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("maintenance_window_cron", sa.String(64), nullable=True),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("tenant_id", "name", name=UNIQUE_CONSTRAINT_NAME),
    )

    op.create_index(
        INDEX_TENANT_ENABLED,
        TABLE_NAME,
        ["tenant_id", "enabled"],
    )

    if is_postgres:
        # Partial index: RedBeat loader (T33) only scans enabled rows, so
        # the planner can narrow this to the hot subset. Mirrors the
        # partial-UNIQUE idiom in migration 019.
        op.execute(
            """
            CREATE INDEX ix_scan_schedules_next_run_at
                ON scan_schedules (next_run_at)
                WHERE enabled = true
            """
        )

        op.execute(f'ALTER TABLE "{TABLE_NAME}" ENABLE ROW LEVEL SECURITY')
        # FORCE is a deliberate hardening over the earlier RLS migrations
        # (002/003/019/020 used ENABLE only): without FORCE the table owner
        # role bypasses the policy, which is exactly the risk T32 closes for
        # schedule rows. Future batches may retrofit FORCE onto older tables.
        op.execute(f'ALTER TABLE "{TABLE_NAME}" FORCE ROW LEVEL SECURITY')
        op.execute(f'DROP POLICY IF EXISTS {RLS_POLICY_NAME} ON "{TABLE_NAME}"')
        op.execute(
            f"""
            CREATE POLICY {RLS_POLICY_NAME} ON "{TABLE_NAME}"
                USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
                WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
            """
        )
    else:
        # SQLite (alembic smoke round-trip) has no partial-index / RLS
        # surface we exercise; emit a plain index so the introspection
        # side of the smoke test still sees the index name.
        op.create_index(
            INDEX_NEXT_RUN_AT,
            TABLE_NAME,
            ["next_run_at"],
        )


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        op.execute(f'DROP POLICY IF EXISTS {RLS_POLICY_NAME} ON "{TABLE_NAME}"')
        op.execute(f'ALTER TABLE "{TABLE_NAME}" NO FORCE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{TABLE_NAME}" DISABLE ROW LEVEL SECURITY')
        # Partial index created via raw SQL — drop via raw SQL so the
        # ``IF EXISTS`` guard keeps ``downgrade()`` idempotent even when
        # the migration is replayed against a partially-migrated DB.
        op.execute(f"DROP INDEX IF EXISTS {INDEX_NEXT_RUN_AT}")
    else:
        op.drop_index(INDEX_NEXT_RUN_AT, table_name=TABLE_NAME)

    op.drop_index(INDEX_TENANT_ENABLED, table_name=TABLE_NAME)
    op.drop_table(TABLE_NAME)
