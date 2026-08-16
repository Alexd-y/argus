"""056 — capabilities, findings occurrences, OAST leases.

Revision ID: 056
Revises: 055
Create Date: 2026-08-15
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "056"
down_revision: str | None = "055"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES: tuple[str, ...] = (
    "asset_capabilities",
    "coverage_requirements",
    "coverage_results",
    "finding_occurrences",
    "finding_assessments",
    "retest_jobs",
    "oast_leases",
    "oast_interactions",
)


def upgrade() -> None:
    bind = op.get_bind()
    json_type = postgresql.JSONB() if bind.dialect.name == "postgresql" else sa.JSON()

    op.create_table(
        "capability_nodes",
        sa.Column("id", sa.String(256), primary_key=True),
        sa.Column("labels", json_type, nullable=False),
        sa.Column("asset_types", json_type, nullable=False),
        sa.Column("execution_modes", json_type, nullable=False),
        sa.Column("production_risk", sa.String(32), nullable=False),
        sa.Column("lab_allowed", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("allowed_phases", json_type, nullable=False),
        sa.Column("evidence_types", json_type, nullable=False),
        sa.Column("tools", json_type, nullable=False),
        sa.Column("attack_techniques", json_type, nullable=False),
        sa.Column("training_only", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("version", sa.String(32), nullable=False, server_default="1"),
    )

    op.create_table(
        "capability_edges",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("src_id", sa.String(256), sa.ForeignKey("capability_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("dst_id", sa.String(256), sa.ForeignKey("capability_nodes.id", ondelete="CASCADE"), nullable=False),
        sa.Column("edge_type", sa.String(64), nullable=False),
        sa.Column("metadata", json_type, nullable=True),
    )

    op.create_table(
        "asset_capabilities",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("capability_ids", json_type, nullable=False),
        sa.Column("profile", json_type, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "coverage_requirements",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("scan_id", sa.String(36), nullable=True),
        sa.Column("capability_id", sa.String(256), nullable=False),
        sa.Column("asset_id", sa.String(36), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="planned"),
        sa.Column("blocked_reason", sa.String(128), nullable=True),
        sa.Column("mode", sa.String(32), nullable=False, server_default="production"),
    )

    op.create_table(
        "coverage_results",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("requirement_id", sa.String(36), sa.ForeignKey("coverage_requirements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("evidence_refs", json_type, nullable=True),
        sa.Column("finding_keys", json_type, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "finding_occurrences",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("finding_key", sa.String(64), nullable=False),
        sa.Column("occurrence_key", sa.String(64), nullable=False),
        sa.Column("scanner", sa.String(64), nullable=False),
        sa.Column("detector_id", sa.String(256), nullable=False),
        sa.Column("detector_version", sa.String(64), nullable=False),
        sa.Column("evidence_refs", json_type, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.UniqueConstraint("tenant_id", "occurrence_key", name="uq_finding_occurrences_tenant_occ"),
    )

    op.create_table(
        "finding_assessments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_key", sa.String(64), nullable=False),
        sa.Column("payload", json_type, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "retest_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("finding_key", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("result", sa.String(32), nullable=True),
        sa.Column("coverage_equivalent", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("payload", json_type, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "oast_leases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), nullable=False),
        sa.Column("scan_id", sa.String(36), nullable=True),
        sa.Column("callback_host", sa.String(512), nullable=False),
        sa.Column("token", sa.String(256), nullable=False),
        sa.Column("mode", sa.String(32), nullable=False, server_default="production"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata", json_type, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    op.create_table(
        "oast_interactions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("lease_id", sa.String(36), sa.ForeignKey("oast_leases.id", ondelete="CASCADE"), nullable=False),
        sa.Column("protocol", sa.String(32), nullable=False),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("raw_ref", sa.String(512), nullable=True),
        sa.Column("correlation_status", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("observed_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP")),
    )

    if bind.dialect.name == "postgresql":
        for table in _TENANT_TABLES:
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
        for table in _TENANT_TABLES:
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
    for table in (
        "oast_interactions",
        "oast_leases",
        "retest_jobs",
        "finding_assessments",
        "finding_occurrences",
        "coverage_results",
        "coverage_requirements",
        "asset_capabilities",
        "capability_edges",
        "capability_nodes",
    ):
        op.drop_table(table)
