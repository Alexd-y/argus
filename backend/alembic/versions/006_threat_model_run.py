"""Threat model runs table — engagement-scoped, traceable via job_id/run_id.

Revision ID: 006
Revises: 005
Create Date: 2026-03-12

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "006"
down_revision: str | None = "005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

THREAT_MODEL_RUNS_TABLE = "threat_model_runs"


def upgrade() -> None:
    op.create_table(
        THREAT_MODEL_RUNS_TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_id", sa.String(36), sa.ForeignKey("recon_targets.id", ondelete="CASCADE"), nullable=True),
        sa.Column("status", sa.String(50), default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("input_bundle_ref", sa.String(1024), nullable=False),
        sa.Column("artifact_refs", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column("job_id", sa.String(200), nullable=False),
        sa.Column("run_id", sa.String(200), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_index("ix_threat_model_runs_engagement", THREAT_MODEL_RUNS_TABLE, ["engagement_id"])
    op.create_index("ix_threat_model_runs_job_run", THREAT_MODEL_RUNS_TABLE, ["job_id", "run_id"])

    op.execute(f'ALTER TABLE "{THREAT_MODEL_RUNS_TABLE}" ENABLE ROW LEVEL SECURITY')
    op.execute(f"""
        CREATE POLICY tenant_isolation ON "{THREAT_MODEL_RUNS_TABLE}"
        USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
        WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
    """)


def downgrade() -> None:
    op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{THREAT_MODEL_RUNS_TABLE}"')
    op.execute(f'ALTER TABLE "{THREAT_MODEL_RUNS_TABLE}" DISABLE ROW LEVEL SECURITY')

    op.drop_index("ix_threat_model_runs_job_run", table_name=THREAT_MODEL_RUNS_TABLE)
    op.drop_index("ix_threat_model_runs_engagement", table_name=THREAT_MODEL_RUNS_TABLE)
    op.drop_table(THREAT_MODEL_RUNS_TABLE)
