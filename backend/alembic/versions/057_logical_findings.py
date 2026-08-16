"""057 — logical_findings + occurrence scan/timeline columns.

Revision ID: 057
Revises: 056
Create Date: 2026-08-16
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "057"
down_revision: str | None = "056"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_RLS_TABLES: tuple[str, ...] = ("logical_findings", "logical_finding_scan_snapshots")


def upgrade() -> None:
    bind = op.get_bind()
    json_type = postgresql.JSONB() if bind.dialect.name == "postgresql" else sa.JSON()

    op.create_table(
        "logical_findings",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_key", sa.String(64), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("state", sa.String(32), nullable=False, server_default="candidate"),
        sa.Column("title", sa.String(500), nullable=False, server_default=""),
        sa.Column("category", sa.String(128), nullable=False, server_default=""),
        sa.Column("evidence_refs", json_type, nullable=False),
        sa.Column("occurrence_keys", json_type, nullable=False),
        sa.Column("scan_ids", json_type, nullable=False),
        sa.Column("coverage_equivalent", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("payload", json_type, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "finding_key", name="pk_logical_findings"),
    )
    op.create_index(
        "ix_logical_findings_tenant_engagement",
        "logical_findings",
        ["tenant_id", "engagement_id"],
    )

    op.create_table(
        "logical_finding_scan_snapshots",
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.String(36), nullable=False),
        sa.Column("finding_key", sa.String(64), nullable=False),
        sa.Column("payload", json_type, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("tenant_id", "scan_id", "finding_key", name="pk_logical_finding_scan_snapshots"),
    )

    op.add_column("finding_occurrences", sa.Column("scan_id", sa.String(36), nullable=True))
    op.add_column("finding_occurrences", sa.Column("first_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("finding_occurrences", sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index(
        "ix_finding_occurrences_tenant_scan",
        "finding_occurrences",
        ["tenant_id", "scan_id"],
    )
    op.create_index(
        "ix_finding_occurrences_tenant_finding",
        "finding_occurrences",
        ["tenant_id", "finding_key"],
    )

    if bind.dialect.name == "postgresql":
        for table in _RLS_TABLES:
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(
                f"""
                CREATE POLICY tenant_isolation ON "{table}"
                USING (tenant_id = current_setting('app.current_tenant_id', true))
                WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true))
                """
            )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in _RLS_TABLES:
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')

    op.drop_index("ix_finding_occurrences_tenant_finding", table_name="finding_occurrences")
    op.drop_index("ix_finding_occurrences_tenant_scan", table_name="finding_occurrences")
    op.drop_column("finding_occurrences", "last_seen_at")
    op.drop_column("finding_occurrences", "first_seen_at")
    op.drop_column("finding_occurrences", "scan_id")
    op.drop_index("ix_logical_findings_tenant_engagement", table_name="logical_findings")
    op.drop_table("logical_finding_scan_snapshots")
    op.drop_table("logical_findings")
