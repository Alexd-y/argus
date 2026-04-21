"""ARG-045 — Persisted report bundle catalogue (s3-backed) + RLS.

Revision ID: 019
Revises: 017
Create Date: 2026-04-21

Context
-------
Cycle 4 ARG-031 closed the 18/18 ReportService matrix (3 tier × 6 format)
but the generated artefacts were still emitted into a per-process
in-memory dict. This migration introduces ``report_bundles`` — a
tenant-scoped index of one row per (scan_id, tier, format) tuple
pointing at the canonical S3 / MinIO blob.

Why a NEW table (and not extending ``reports``)
-----------------------------------------------
``reports`` (rev 001 + 009) is one-row-per-scan with summary metadata
(``tier``, ``generation_status``, ``requested_formats`` JSONB). It does
NOT model the per-format file artefacts.  The Cycle 5 spec for
ARG-045 calls for a per-format catalogue with ``s3_key`` + ``byte_size``;
making it a separate ``report_bundles`` table avoids destructive DDL on
the existing ``reports`` table (KEEP the additive-only invariant) and
keeps the new surface backwards-compatible.

Schema
------
``report_bundles`` columns (all NOT NULL except ``deleted_at``):
  * report_bundle_id : VARCHAR(36)  — UUID PK
  * tenant_id        : VARCHAR(36)  — FK tenants(id) ON DELETE CASCADE
  * scan_id          : VARCHAR(36)  — FK scans(id)   ON DELETE CASCADE
  * tier             : VARCHAR(32)  — midgard | asgard | valhalla (CHECK)
  * format           : VARCHAR(16)  — html | json | csv | pdf | sarif | xml (CHECK)
  * s3_key           : VARCHAR(1024) — opaque MinIO/S3 object key
  * byte_size        : BIGINT       — content-length in bytes
  * sha256           : VARCHAR(64)  — content hash for cache-busting
  * created_at       : TIMESTAMPTZ  — server_default now()
  * deleted_at       : TIMESTAMPTZ  — soft-delete pointer (NULL = live)

Indexes:
  * ix_report_bundles_scan_tier_format  — covering the hot lookup
    (one bundle per (scan, tier, format)) — UNIQUE constraint
    excluding soft-deleted rows.
  * ix_report_bundles_tenant_created    — list-by-tenant pagination.

Row-Level Security
------------------
``tenant_isolation`` policy mirrors every other tenant-scoped table
in the schema (see ``002_rls_and_audit_immutable.py`` for the master
pattern). ``current_setting('app.current_tenant_id', true)`` is set by
``backend/src/db/session.py::set_tenant_context()`` at the start of
every request via the FastAPI dependency stack.

Backwards compatibility
-----------------------
* No columns removed.
* No constraints added to existing tables.
* downgrade() drops the table and the policy in the reverse order.
* Round-trip schema diff = 0 (enforced by
  ``backend/tests/integration/migrations/test_alembic_smoke.py``).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "019"
down_revision: str | None = "017"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE_NAME = "report_bundles"

ALLOWED_TIERS = ("midgard", "asgard", "valhalla")
ALLOWED_FORMATS = ("html", "json", "csv", "pdf", "sarif", "xml")


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    op.create_table(
        TABLE_NAME,
        sa.Column("report_bundle_id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "scan_id",
            sa.String(36),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("tier", sa.String(32), nullable=False),
        sa.Column("format", sa.String(16), nullable=False),
        sa.Column("s3_key", sa.String(1024), nullable=False),
        sa.Column("byte_size", sa.BigInteger(), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            f"tier IN ({', '.join(repr(t) for t in ALLOWED_TIERS)})",
            name="ck_report_bundles_tier",
        ),
        sa.CheckConstraint(
            f"format IN ({', '.join(repr(f) for f in ALLOWED_FORMATS)})",
            name="ck_report_bundles_format",
        ),
        sa.CheckConstraint("byte_size >= 0", name="ck_report_bundles_byte_size_nonneg"),
    )

    op.create_index(
        "ix_report_bundles_tenant_created",
        TABLE_NAME,
        ["tenant_id", "created_at"],
    )

    if is_postgres:
        # Partial UNIQUE: at most one live bundle per (scan, tier, format).
        # A re-generation soft-deletes the previous bundle (sets deleted_at)
        # and inserts a fresh row, so historical retention stays auditable
        # without colliding with the uniqueness invariant.
        op.execute(
            """
            CREATE UNIQUE INDEX ix_report_bundles_scan_tier_format
                ON report_bundles (scan_id, tier, format)
                WHERE deleted_at IS NULL
            """
        )

        op.execute("ALTER TABLE report_bundles ENABLE ROW LEVEL SECURITY")
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON report_bundles")
        op.execute(
            """
            CREATE POLICY tenant_isolation ON report_bundles
                USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
                WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
            """
        )
    else:
        # SQLite (used by the schema-diff smoke test): emulate the partial
        # UNIQUE with a regular UNIQUE — the soft-delete contract is
        # enforced at the application layer in non-prod backends.
        op.create_index(
            "ix_report_bundles_scan_tier_format",
            TABLE_NAME,
            ["scan_id", "tier", "format"],
            unique=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON report_bundles")
        op.execute("ALTER TABLE report_bundles DISABLE ROW LEVEL SECURITY")

    op.drop_index("ix_report_bundles_scan_tier_format", table_name=TABLE_NAME)
    op.drop_index("ix_report_bundles_tenant_created", table_name=TABLE_NAME)
    op.drop_table(TABLE_NAME)
