"""Phase 4 — multi-model gateway, benchmarks, release governance, research

Revision ID: 036
Revises: 035_phase3_binary_incidents_integrations
Create Date: 2026-05-11

Tables:
  - gateway_invocations: detailed LLM call logs
  - gateway_providers: provider configuration
  - benchmark_runs: evaluation suite executions
  - benchmark_results: per-run metrics
  - release_gates: gate check history
  - release_cards: system cards per model version
  - research_artifacts: analyst workbench outputs
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "036"
down_revision: Union[str, None] = "035"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table("gateway_providers",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("alias", sa.String(64), nullable=False),
        sa.Column("provider_key", sa.String(64), nullable=False),
        sa.Column("model", sa.String(128)),
        sa.Column("base_url", sa.String(512)),
        sa.Column("role", sa.String(32)),
        sa.Column("cloud_allowed", sa.Boolean, server_default=sa.text("true")),
        sa.Column("enabled", sa.Boolean, server_default=sa.text("true")),
        sa.Column("config_json", JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.execute("ALTER TABLE gateway_providers ENABLE ROW LEVEL SECURITY")
    op.execute("CREATE POLICY gw_providers_tenant ON gateway_providers USING (tenant_id = current_setting('app.current_tenant_id'))")

    op.create_table("gateway_invocations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("scan_id", sa.String(36)),
        sa.Column("phase", sa.String(32)),
        sa.Column("task", sa.String(32)),
        sa.Column("alias", sa.String(64)),
        sa.Column("provider", sa.String(64)),
        sa.Column("model", sa.String(128)),
        sa.Column("prompt_hash", sa.String(64)),
        sa.Column("response_hash", sa.String(64)),
        sa.Column("prompt_tokens", sa.Integer, server_default=sa.text("0")),
        sa.Column("completion_tokens", sa.Integer, server_default=sa.text("0")),
        sa.Column("estimated_cost_usd", sa.Float, server_default=sa.text("0.0")),
        sa.Column("latency_ms", sa.Integer, server_default=sa.text("0")),
        sa.Column("status", sa.String(20), server_default="completed"),
        sa.Column("error_code", sa.String(32)),
        sa.Column("policy_decision", JSONB),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Index("ix_gw_invocations_scan", "scan_id"),
    )

    op.create_table("benchmark_runs",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(128)),
        sa.Column("model", sa.String(128)),
        sa.Column("profile", sa.String(32)),
        sa.Column("datasets", JSONB),
        sa.Column("metrics_json", JSONB),
        sa.Column("status", sa.String(20), server_default="pending"),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.Column("duration_s", sa.Float, server_default=sa.text("0.0")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table("release_gates",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("model", sa.String(128)),
        sa.Column("version", sa.String(32)),
        sa.Column("status", sa.String(20), server_default="draft"),
        sa.Column("eval_delta", JSONB),
        sa.Column("gates_check", JSONB),
        sa.Column("system_card_id", sa.String(36)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table("research_artifacts",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), nullable=False, index=True),
        sa.Column("artifact_type", sa.String(32)),
        sa.Column("title", sa.String(256)),
        sa.Column("content_json", JSONB),
        sa.Column("created_by", sa.String(64)),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("research_artifacts")
    op.drop_table("release_gates")
    op.drop_table("benchmark_runs")
    op.drop_table("gateway_invocations")
    op.drop_table("gateway_providers")
