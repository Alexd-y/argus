"""Phase 3 — binary triage, incident enrichment, integrations, compliance, safety

Revision ID: 035
Revises: 034_phase2_sandbox_patches_rbac
Create Date: 2026-05-11

Tables:
  - binary_analyses: static analysis results
  - binary_dynamic_runs: dynamic execution results
  - binary_custody: chain-of-custody records
  - incident_enrichments: alert-to-code correlation
  - integration_logs: SIEM/SOAR/ITSM send history
  - compliance_evidence: per-framework evidence records
  - safety_alerts: anomaly detection events
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "035"
down_revision: Union[str, None] = "034"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table("binary_analyses",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("sample_id", sa.String(36)),
        sa.Column("file_path", sa.String(1024)),
        sa.Column("file_size", sa.Integer, server_default=sa.text("0")),
        sa.Column("sha256", sa.String(64)),
        sa.Column("format", sa.String(16)),
        sa.Column("architecture", sa.String(32)),
        sa.Column("verdict", sa.String(32)),
        sa.Column("risk_score", sa.Float, server_default=sa.text("0.0")),
        sa.Column("obfuscation_score", sa.Float, server_default=sa.text("0.0")),
        sa.Column("packer_hints", JSONB),
        sa.Column("capabilities", JSONB),
        sa.Column("mitre_attck", JSONB),
        sa.Column("wb_analysis", JSONB),
        sa.Column("indicators", JSONB),
        sa.Column("error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.execute("ALTER TABLE binary_analyses ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY binary_analyses_tenant_isolation ON binary_analyses USING (tenant_id = current_setting('app.current_tenant_id'))")

    op.create_table("binary_dynamic_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("sample_id", sa.String(36)),
        sa.Column("execution_time_ms", sa.Integer, server_default=sa.text("0")),
        sa.Column("exit_code", sa.Integer, server_default=sa.text("-1")),
        sa.Column("verdict", sa.String(32)),
        sa.Column("processes_spawned", JSONB),
        sa.Column("network_connections", JSONB),
        sa.Column("file_operations", JSONB),
        sa.Column("error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table("binary_custody",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("sample_id", sa.String(36)),
        sa.Column("submitted_by", sa.String(64)),
        sa.Column("status", sa.String(20), server_default="received"),
        sa.Column("quarantine_path", sa.String(1024)),
        sa.Column("hash_before", sa.String(64)),
        sa.Column("custody_chain", JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table("incident_enrichments",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("incident_id", sa.String(36)),
        sa.Column("alert_id", sa.String(36)),
        sa.Column("code_root_cause", sa.Text),
        sa.Column("file_path", sa.String(1024)),
        sa.Column("owner_team", sa.String(128)),
        sa.Column("repo", sa.String(256)),
        sa.Column("cloud_asset", sa.String(256)),
        sa.Column("mitre_enrichment", JSONB),
        sa.Column("cwe_mapping", JSONB),
        sa.Column("remediation_tasks", JSONB),
        sa.Column("confidence", sa.Float, server_default=sa.text("0.0")),
        sa.Column("enriched_at", sa.DateTime(timezone=True)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table("integration_logs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("provider", sa.String(32)),
        sa.Column("action", sa.String(32)),
        sa.Column("success", sa.Boolean, server_default=sa.text("false")),
        sa.Column("external_id", sa.String(128)),
        sa.Column("error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table("compliance_evidence",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("finding_id", sa.String(36)),
        sa.Column("framework", sa.String(32)),
        sa.Column("control_id", sa.String(32)),
        sa.Column("evidence_type", sa.String(32)),
        sa.Column("evidence_description", sa.Text),
        sa.Column("evidence_hash", sa.String(64)),
        sa.Column("validity_days", sa.Integer, server_default=sa.text("365")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table("safety_alerts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), index=True),
        sa.Column("alert_type", sa.String(64)),
        sa.Column("severity", sa.String(16)),
        sa.Column("description", sa.Text),
        sa.Column("model", sa.String(64)),
        sa.Column("task", sa.String(32)),
        sa.Column("prompt_hash", sa.String(64)),
        sa.Column("evidence", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("safety_alerts")
    op.drop_table("compliance_evidence")
    op.drop_table("integration_logs")
    op.drop_table("incident_enrichments")
    op.drop_table("binary_custody")
    op.drop_table("binary_dynamic_runs")
    op.drop_table("binary_analyses")
