"""058 — Quick execution mode tables + scans.execution_mode columns.

Revision ID: 058
Revises: 057
Create Date: 2026-08-16

Adds immutable ``execution_mode=quick`` persistence. Quick uses production-like
policy (never LAB allow-all). ``scan_mode=quick`` (depth) is unchanged.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "058"
down_revision: str | None = "057"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES: tuple[str, ...] = (
    "quick_scan_configs",
    "quick_scan_plans",
    "quick_tasks",
    "quick_budget_leases",
)


def upgrade() -> None:
    bind = op.get_bind()
    json_type = postgresql.JSONB() if bind.dialect.name == "postgresql" else sa.JSON()

    op.add_column(
        "scans",
        sa.Column(
            "execution_mode",
            sa.String(32),
            nullable=False,
            server_default="production",
        ),
    )
    op.add_column(
        "scans",
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "scans",
        sa.Column("quick_profile", sa.String(32), nullable=True),
    )
    op.create_index(
        "ix_scans_tenant_execution_mode",
        "scans",
        ["tenant_id", "execution_mode"],
    )

    op.create_table(
        "quick_scan_configs",
        sa.Column("id", sa.String(36), primary_key=True),
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
        sa.Column("profile", sa.String(32), nullable=False),
        sa.Column("wall_clock_budget_seconds", sa.Integer(), nullable=False),
        sa.Column("ai_budget_seconds", sa.Integer(), nullable=False),
        sa.Column("reserve_for_validation_percent", sa.Integer(), nullable=False),
        sa.Column("max_targets", sa.Integer(), nullable=False),
        sa.Column("max_urls_per_host", sa.Integer(), nullable=False),
        sa.Column("crawl_depth", sa.Integer(), nullable=False),
        sa.Column("severity_floor", sa.String(32), nullable=False),
        sa.Column("enable_ai", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("enable_oast", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "enable_headless_on_signal",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column("authenticated_context_id", sa.String(36), nullable=True),
        sa.Column(
            "template_policy_id",
            sa.String(128),
            nullable=False,
            server_default="quick-default",
        ),
        sa.Column(
            "cloud_llm_allowed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload", json_type, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.UniqueConstraint("scan_id", name="uq_quick_scan_configs_scan_id"),
    )
    op.create_index(
        "ix_quick_scan_configs_tenant_scan",
        "quick_scan_configs",
        ["tenant_id", "scan_id"],
    )
    op.create_index("ix_quick_scan_configs_deadline", "quick_scan_configs", ["deadline_at"])

    op.create_table(
        "quick_scan_plans",
        sa.Column("id", sa.String(36), primary_key=True),
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
        sa.Column("plan_version", sa.Integer(), nullable=False),
        sa.Column("prompt_version", sa.String(128), nullable=False),
        sa.Column("model_route", sa.String(128), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("budget", json_type, nullable=False),
        sa.Column("stages", json_type, nullable=False),
        sa.Column("tasks", json_type, nullable=False),
        sa.Column("fallbacks", json_type, nullable=False),
        sa.Column("coverage_intent", json_type, nullable=False),
        sa.Column("assumptions", json_type, nullable=False),
        sa.Column("revision_reason", sa.String(512), nullable=True),
        sa.Column("evidence_ids", json_type, nullable=True),
        sa.Column("cost_estimate_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.UniqueConstraint("scan_id", "plan_version", name="uq_quick_scan_plans_scan_version"),
    )
    op.create_index(
        "ix_quick_scan_plans_tenant_scan",
        "quick_scan_plans",
        ["tenant_id", "scan_id"],
    )

    op.create_table(
        "quick_tasks",
        sa.Column("id", sa.String(36), primary_key=True),
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
        sa.Column(
            "plan_id",
            sa.String(36),
            sa.ForeignKey("quick_scan_plans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("stage", sa.String(32), nullable=False),
        sa.Column("target_ref", sa.String(256), nullable=False),
        sa.Column("tool_id", sa.String(128), nullable=False),
        sa.Column("capability_id", sa.String(256), nullable=False),
        sa.Column("estimated_seconds", sa.Integer(), nullable=False),
        sa.Column("estimated_requests", sa.Integer(), nullable=False),
        sa.Column("priority_score", sa.Float(), nullable=False),
        sa.Column("depends_on", json_type, nullable=True),
        sa.Column("success_signal", json_type, nullable=True),
        sa.Column("stop_conditions", json_type, nullable=True),
        sa.Column("policy_decision_id", sa.String(36), nullable=True),
        sa.Column("budget_lease_id", sa.String(36), nullable=True),
        sa.Column("idempotency_key", sa.String(256), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="queued"),
        sa.Column("celery_task_id", sa.String(64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.UniqueConstraint("idempotency_key", name="uq_quick_tasks_idempotency_key"),
    )
    op.create_index(
        "ix_quick_tasks_tenant_scan",
        "quick_tasks",
        ["tenant_id", "scan_id"],
    )
    op.create_index(
        "ix_quick_tasks_plan_status",
        "quick_tasks",
        ["plan_id", "status"],
    )

    op.create_table(
        "quick_budget_leases",
        sa.Column("id", sa.String(36), primary_key=True),
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
        sa.Column(
            "task_id",
            sa.String(36),
            sa.ForeignKey("quick_tasks.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("granted", sa.Integer(), nullable=False),
        sa.Column("consumed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_quick_budget_leases_tenant_scan",
        "quick_budget_leases",
        ["tenant_id", "scan_id"],
    )
    op.create_index(
        "ix_quick_budget_leases_status_expires",
        "quick_budget_leases",
        ["status", "expires_at"],
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

    op.drop_table("quick_budget_leases")
    op.drop_table("quick_tasks")
    op.drop_table("quick_scan_plans")
    op.drop_table("quick_scan_configs")
    op.drop_index("ix_scans_tenant_execution_mode", table_name="scans")
    op.drop_column("scans", "quick_profile")
    op.drop_column("scans", "deadline_at")
    op.drop_column("scans", "execution_mode")
