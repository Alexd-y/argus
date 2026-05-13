"""Phase 2 — sandbox validation, patches, risk scores, ABAC

Revision ID: 034
Revises: 033_phase1_ingestion_knowledge_graph
Create Date: 2026-05-11

Tables:
  - sandbox_runs: validation execution records
  - sandbox_artifacts: evidence artifacts per run
  - patche_proposals: AI-generated patch suggestions
  - risk_scores: CVSS + business-context scores
  - abac_policies: attribute-based access policies
  - access_audit_log: per-request audit trail (immutable)
  - approval_workflows: multi-step review chains
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "034"
down_revision: Union[str, None] = "033"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # sandbox_runs
    op.create_table(
        "sandbox_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("scan_id", sa.String(36)),
        sa.Column("finding_id", sa.String(36)),
        sa.Column("profile", sa.String(32), server_default="web_app"),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("exploitable", sa.Boolean, server_default=sa.text("false")),
        sa.Column("confidence", sa.Float, server_default=sa.text("0.0")),
        sa.Column("exit_code", sa.Integer, server_default=sa.text("-1")),
        sa.Column("stdout_preview", sa.Text),
        sa.Column("stderr_preview", sa.Text),
        sa.Column("results_json", JSONB),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("duration_ms", sa.Integer, server_default=sa.text("0")),
        sa.Column("error", sa.Text),
        sa.Column("policy_breaches", JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.execute("ALTER TABLE sandbox_runs ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY sandbox_runs_tenant_isolation ON sandbox_runs USING (tenant_id = current_setting('app.current_tenant_id'))")

    # sandbox_artifacts
    op.create_table(
        "sandbox_artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("sandbox_run_id", sa.String(36), nullable=False),
        sa.Column("artifact_type", sa.String(32), server_default="log"),
        sa.Column("content_hash", sa.String(64)),
        sa.Column("storage_key", sa.String(512)),
        sa.Column("size_bytes", sa.Integer, server_default=sa.text("0")),
        sa.Column("metadata", JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["sandbox_run_id"], ["sandbox_runs.id"], ondelete="CASCADE"),
    )

    # patche_proposals
    op.create_table(
        "patche_proposals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("repo_id", sa.String(36)),
        sa.Column("finding_id", sa.String(36)),
        sa.Column("patch_type", sa.String(16), server_default="minimal"),
        sa.Column("file_path", sa.String(1024)),
        sa.Column("line_start", sa.Integer, server_default=sa.text("0")),
        sa.Column("original_code", sa.Text),
        sa.Column("patched_code", sa.Text),
        sa.Column("diff", sa.Text),
        sa.Column("rationale", sa.Text),
        sa.Column("secure_alternative", sa.Text),
        sa.Column("blast_radius", sa.Text),
        sa.Column("backward_compat_risk", sa.String(16), server_default="low"),
        sa.Column("regression_test", sa.Text),
        sa.Column("validation_output", sa.Text),
        sa.Column("lint_passed", sa.Boolean, server_default=sa.text("false")),
        sa.Column("tests_passed", sa.Boolean, server_default=sa.text("false")),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("pr_url", sa.String(512)),
        sa.Column("error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.execute("ALTER TABLE patche_proposals ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY patches_tenant_isolation ON patche_proposals USING (tenant_id = current_setting('app.current_tenant_id'))")

    # risk_scores
    op.create_table(
        "risk_scores",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("finding_id", sa.String(36)),
        sa.Column("cvss_base", sa.Float, server_default=sa.text("0.0")),
        sa.Column("cvss_temporal", sa.Float, server_default=sa.text("0.0")),
        sa.Column("cvss_environmental", sa.Float, server_default=sa.text("0.0")),
        sa.Column("exploitability_score", sa.Float, server_default=sa.text("0.0")),
        sa.Column("impact_score", sa.Float, server_default=sa.text("0.0")),
        sa.Column("business_impact", sa.Float, server_default=sa.text("0.0")),
        sa.Column("overall_score", sa.Float, server_default=sa.text("0.0")),
        sa.Column("priority", sa.String(20), server_default="p4_low"),
        sa.Column("vector_string", sa.String(128)),
        sa.Column("reasoning", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # abac_policies
    op.create_table(
        "abac_policies",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("resource_type", sa.String(32), nullable=False),
        sa.Column("allowed_actions", JSONB, nullable=False),
        sa.Column("conditions", JSONB),
        sa.Column("enabled", sa.Boolean, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    # access_audit_log (immutable append-only)
    op.create_table(
        "access_audit_log",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("user_id", sa.String(36)),
        sa.Column("role", sa.String(32)),
        sa.Column("action", sa.String(32)),
        sa.Column("resource_type", sa.String(32)),
        sa.Column("resource_id", sa.String(36)),
        sa.Column("allowed", sa.Boolean, server_default=sa.text("false")),
        sa.Column("reason", sa.String(256)),
        sa.Column("watermark", sa.String(64)),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("user_agent", sa.String(512)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.execute("ALTER TABLE access_audit_log ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY audit_tenant_isolation ON access_audit_log USING (tenant_id = current_setting('app.current_tenant_id'))")

    # approval_workflows
    op.create_table(
        "approval_workflows",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("requester_id", sa.String(36)),
        sa.Column("approver_id", sa.String(36)),
        sa.Column("resource_type", sa.String(32)),
        sa.Column("resource_id", sa.String(36)),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("comments", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("approved_at", sa.DateTime(timezone=True)),
    )
    op.execute("ALTER TABLE approval_workflows ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY approvals_tenant_isolation ON approval_workflows USING (tenant_id = current_setting('app.current_tenant_id'))")


def downgrade() -> None:
    op.drop_table("approval_workflows")
    op.drop_table("access_audit_log")
    op.drop_table("abac_policies")
    op.drop_table("risk_scores")
    op.drop_table("patche_proposals")
    op.drop_table("sandbox_artifacts")
    op.drop_table("sandbox_runs")
