"""Recon module — engagements, recon_targets, scan_jobs, artifacts, normalized_findings, hypotheses.

Revision ID: 005
Revises: 004
Create Date: 2026-03-11

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "005"
down_revision: Union[str, None] = "004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

RECON_TENANT_SCOPED_TABLES = [
    "engagements",
    "recon_targets",
    "scan_jobs",
    "artifacts",
    "normalized_findings",
    "hypotheses",
]


def upgrade() -> None:
    # 1. engagements
    op.create_table(
        "engagements",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(50), default="draft"),
        sa.Column("scope_config", postgresql.JSONB(), nullable=True),
        sa.Column("contacts", postgresql.JSONB(), nullable=True),
        sa.Column("environment", sa.String(50), default="production"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 2. recon_targets (FK → engagements)
    op.create_table(
        "recon_targets",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("domain", sa.String(512), nullable=False),
        sa.Column("target_type", sa.String(50), default="domain"),
        sa.Column("extra_data", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 3. scan_jobs (FK → engagements, recon_targets)
    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("recon_targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("stage", sa.Integer(), nullable=False),
        sa.Column("stage_name", sa.String(100), nullable=False),
        sa.Column("tool_name", sa.String(100), nullable=False),
        sa.Column("status", sa.String(50), default="pending"),
        sa.Column("config", postgresql.JSONB(), nullable=True),
        sa.Column("result_summary", postgresql.JSONB(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("operator", sa.String(255), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 4. artifacts (FK → engagements, recon_targets, scan_jobs)
    op.create_table(
        "artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("recon_targets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("job_id", sa.String(36), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=True),
        sa.Column("artifact_type", sa.String(50), nullable=False),
        sa.Column("stage", sa.Integer(), nullable=True),
        sa.Column("filename", sa.String(512), nullable=False),
        sa.Column("content_type", sa.String(100), default="text/plain"),
        sa.Column("object_key", sa.String(1024), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=True),
        sa.Column("checksum_sha256", sa.String(64), nullable=True),
        sa.Column("extra_data", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 5. normalized_findings (FK → engagements, recon_targets, scan_jobs)
    op.create_table(
        "normalized_findings",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("recon_targets.id", ondelete="CASCADE"), nullable=False),
        sa.Column("job_id", sa.String(36), sa.ForeignKey("scan_jobs.id", ondelete="CASCADE"), nullable=True),
        sa.Column("finding_type", sa.String(50), nullable=False),
        sa.Column("value", sa.String(2048), nullable=False),
        sa.Column("data", postgresql.JSONB(), nullable=False),
        sa.Column("source_tool", sa.String(100), nullable=False),
        sa.Column("confidence", sa.Float(), default=1.0),
        sa.Column("is_verified", sa.Boolean(), default=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # 6. hypotheses (FK → engagements, recon_targets)
    op.create_table(
        "hypotheses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("recon_targets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("priority", sa.String(20), default="medium"),
        sa.Column("evidence_refs", postgresql.JSONB(), nullable=True),
        sa.Column("status", sa.String(50), default="pending"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # Indexes
    op.create_index("ix_engagements_tenant_status", "engagements", ["tenant_id", "status"])

    op.create_index("ix_recon_targets_engagement", "recon_targets", ["engagement_id"])
    op.create_unique_constraint("uq_recon_targets_engagement_domain", "recon_targets", ["engagement_id", "domain"])

    op.create_index("ix_scan_jobs_engagement_target_stage", "scan_jobs", ["engagement_id", "target_id", "stage"])
    op.create_index("ix_scan_jobs_tenant_status", "scan_jobs", ["tenant_id", "status"])

    op.create_index("ix_artifacts_engagement_type", "artifacts", ["engagement_id", "artifact_type"])
    op.create_index("ix_artifacts_job", "artifacts", ["job_id"])

    op.create_index("ix_nf_engagement_type", "normalized_findings", ["engagement_id", "finding_type"])
    op.create_unique_constraint("uq_nf_target_type_value", "normalized_findings", ["target_id", "finding_type", "value"])
    op.create_index("ix_nf_data_gin", "normalized_findings", ["data"], postgresql_using="gin")

    op.create_index("ix_hypotheses_engagement_priority", "hypotheses", ["engagement_id", "priority"])

    # Enable RLS on all recon tables
    for table in RECON_TENANT_SCOPED_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f"""
            CREATE POLICY tenant_isolation ON "{table}"
            USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
            WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
        """)


def downgrade() -> None:
    # Remove RLS policies
    for table in reversed(RECON_TENANT_SCOPED_TABLES):
        op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
        op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')

    # Drop indexes
    op.drop_index("ix_hypotheses_engagement_priority", table_name="hypotheses")

    op.drop_index("ix_nf_data_gin", table_name="normalized_findings")
    op.drop_constraint("uq_nf_target_type_value", "normalized_findings", type_="unique")
    op.drop_index("ix_nf_engagement_type", table_name="normalized_findings")

    op.drop_index("ix_artifacts_job", table_name="artifacts")
    op.drop_index("ix_artifacts_engagement_type", table_name="artifacts")

    op.drop_index("ix_scan_jobs_tenant_status", table_name="scan_jobs")
    op.drop_index("ix_scan_jobs_engagement_target_stage", table_name="scan_jobs")

    op.drop_constraint("uq_recon_targets_engagement_domain", "recon_targets", type_="unique")
    op.drop_index("ix_recon_targets_engagement", table_name="recon_targets")

    op.drop_index("ix_engagements_tenant_status", table_name="engagements")

    # Drop tables in reverse FK dependency order
    op.drop_table("hypotheses")
    op.drop_table("normalized_findings")
    op.drop_table("artifacts")
    op.drop_table("scan_jobs")
    op.drop_table("recon_targets")
    op.drop_table("engagements")
