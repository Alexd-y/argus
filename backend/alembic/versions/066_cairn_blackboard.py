"""066 — Cairn Fact-Intent blackboard subsystem (Phase 1).

Ports the upstream Cairn SQLite schema (``_external/Cairn/cairn/src/cairn/server/db.py``,
AGPL-3.0) onto PostgreSQL with ARGUS conventions: ``String(36)`` UUID PKs, per-tenant
RLS, human-readable scoped ref counters, fence tokens for distributed writers, and
durable task-run / worker-backoff tables that replace upstream in-memory state.

Idempotent: tables are only created when absent. RLS mirrors ``002`` — every
tenant-scoped table isolates by ``current_setting('app.current_tenant_id')``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "066"
down_revision: str | None = "065"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# All new tables carry ``tenant_id`` and get RLS + tenant-isolation policy.
_RLS_TABLES: tuple[str, ...] = (
    "cairn_projects",
    "cairn_facts",
    "cairn_intents",
    "cairn_intent_sources",
    "cairn_hints",
    "cairn_settings",
    "cairn_scoped_counters",
    "cairn_tenant_counters",
    "cairn_task_runs",
    "cairn_worker_backoff",
)

# Reverse dependency order for clean drops.
_DROP_ORDER: tuple[str, ...] = (
    "cairn_worker_backoff",
    "cairn_task_runs",
    "cairn_tenant_counters",
    "cairn_scoped_counters",
    "cairn_settings",
    "cairn_hints",
    "cairn_intent_sources",
    "cairn_intents",
    "cairn_facts",
    "cairn_projects",
)


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return name in set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    if not _has_table("cairn_projects"):
        op.create_table(
            "cairn_projects",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("ref", sa.String(length=32), nullable=False),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "scan_id",
                sa.String(length=36),
                sa.ForeignKey("scans.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("engagement_id", sa.String(length=36), nullable=True),
            sa.Column("title", sa.String(length=500), nullable=False),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="active"),
            sa.Column(
                "bootstrap_enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")
            ),
            sa.Column(
                "execution_mode", sa.String(length=32), nullable=False, server_default="production"
            ),
            sa.Column("origin_fact_id", sa.String(length=36), nullable=True),
            sa.Column("goal_fact_id", sa.String(length=36), nullable=True),
            sa.Column("reason_worker", sa.String(length=128), nullable=True),
            sa.Column("reason_trigger", sa.String(length=128), nullable=True),
            sa.Column("reason_started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("reason_last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "reason_fence_token", sa.BigInteger(), nullable=False, server_default=sa.text("0")
            ),
            sa.Column("budget_usd_limit", sa.Numeric(12, 4), nullable=True),
            sa.Column("max_iterations", sa.Integer(), nullable=True),
            sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("options", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.UniqueConstraint("tenant_id", "ref", name="uq_cairn_projects_tenant_ref"),
            sa.CheckConstraint(
                "status IN ('active','stopped','completed')", name="ck_cairn_projects_status"
            ),
        )
        op.create_index(
            "ix_cairn_projects_tenant_status", "cairn_projects", ["tenant_id", "status"]
        )
        op.create_index("ix_cairn_projects_scan", "cairn_projects", ["scan_id"])

    if not _has_table("cairn_facts"):
        op.create_table(
            "cairn_facts",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("ref", sa.String(length=16), nullable=False),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "project_id",
                sa.String(length=36),
                sa.ForeignKey("cairn_projects.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("created_by", sa.String(length=128), nullable=False, server_default="system"),
            sa.Column("source_task_type", sa.String(length=16), nullable=True),
            sa.Column(
                "evidence_refs", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
            ),
            sa.Column("evidence_tier", sa.Integer(), nullable=True),
            sa.Column("confidence", sa.Float(), nullable=True),
            sa.Column("artifact_object_key", sa.String(length=1024), nullable=True),
            sa.Column("finding_id", sa.String(length=36), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.UniqueConstraint("project_id", "ref", name="uq_cairn_facts_project_ref"),
        )
        op.create_index("ix_cairn_facts_project", "cairn_facts", ["project_id"])
        op.create_index("ix_cairn_facts_tenant", "cairn_facts", ["tenant_id"])

    if not _has_table("cairn_intents"):
        op.create_table(
            "cairn_intents",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("ref", sa.String(length=16), nullable=False),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "project_id",
                sa.String(length=36),
                sa.ForeignKey("cairn_projects.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "to_fact_id",
                sa.String(length=36),
                sa.ForeignKey("cairn_facts.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column(
                "is_completion", sa.Boolean(), nullable=False, server_default=sa.text("false")
            ),
            sa.Column("description", sa.Text(), nullable=False),
            sa.Column("creator", sa.String(length=128), nullable=False),
            sa.Column("worker", sa.String(length=128), nullable=True),
            sa.Column("last_heartbeat_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("fence_token", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("last_error", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column("concluded_at", sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint("project_id", "ref", name="uq_cairn_intents_project_ref"),
        )
        op.create_index(
            "ix_cairn_intents_open", "cairn_intents", ["project_id", "to_fact_id", "worker"]
        )
        op.create_index("ix_cairn_intents_tenant", "cairn_intents", ["tenant_id"])

    if not _has_table("cairn_intent_sources"):
        op.create_table(
            "cairn_intent_sources",
            sa.Column(
                "intent_id",
                sa.String(length=36),
                sa.ForeignKey("cairn_intents.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column(
                "fact_id",
                sa.String(length=36),
                sa.ForeignKey("cairn_facts.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("position", sa.Integer(), nullable=False, server_default=sa.text("0")),
        )
        op.create_index("ix_cairn_intent_sources_fact", "cairn_intent_sources", ["fact_id"])

    if not _has_table("cairn_hints"):
        op.create_table(
            "cairn_hints",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("ref", sa.String(length=16), nullable=False),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "project_id",
                sa.String(length=36),
                sa.ForeignKey("cairn_projects.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("content", sa.Text(), nullable=False),
            sa.Column("creator", sa.String(length=128), nullable=False),
            sa.Column("author_user_id", sa.String(length=36), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.UniqueConstraint("project_id", "ref", name="uq_cairn_hints_project_ref"),
        )
        op.create_index("ix_cairn_hints_project", "cairn_hints", ["project_id"])

    if not _has_table("cairn_settings"):
        op.create_table(
            "cairn_settings",
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column(
                "intent_timeout", sa.Integer(), nullable=False, server_default=sa.text("900")
            ),
            sa.Column(
                "reason_timeout", sa.Integer(), nullable=False, server_default=sa.text("900")
            ),
            sa.Column("max_intents", sa.Integer(), nullable=False, server_default=sa.text("3")),
            sa.Column("max_workers", sa.Integer(), nullable=False, server_default=sa.text("8")),
            sa.Column(
                "max_running_projects", sa.Integer(), nullable=False, server_default=sa.text("3")
            ),
            sa.Column(
                "max_project_workers", sa.Integer(), nullable=False, server_default=sa.text("4")
            ),
            sa.Column(
                "tick_interval_sec", sa.Integer(), nullable=False, server_default=sa.text("10")
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.CheckConstraint("intent_timeout >= 5", name="ck_cairn_settings_intent_timeout"),
            sa.CheckConstraint("reason_timeout >= 5", name="ck_cairn_settings_reason_timeout"),
        )

    if not _has_table("cairn_scoped_counters"):
        op.create_table(
            "cairn_scoped_counters",
            sa.Column(
                "project_id",
                sa.String(length=36),
                sa.ForeignKey("cairn_projects.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column("kind", sa.String(length=16), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("value", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.CheckConstraint(
                "kind IN ('fact','intent','hint')", name="ck_cairn_scoped_counter_kind"
            ),
        )

    if not _has_table("cairn_tenant_counters"):
        op.create_table(
            "cairn_tenant_counters",
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column("kind", sa.String(length=16), primary_key=True),
            sa.Column("value", sa.Integer(), nullable=False, server_default=sa.text("0")),
        )

    if not _has_table("cairn_task_runs"):
        op.create_table(
            "cairn_task_runs",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "project_id",
                sa.String(length=36),
                sa.ForeignKey("cairn_projects.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "intent_id",
                sa.String(length=36),
                sa.ForeignKey("cairn_intents.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("task_type", sa.String(length=16), nullable=False),
            sa.Column("worker_name", sa.String(length=128), nullable=False),
            sa.Column("state", sa.String(length=16), nullable=False, server_default="queued"),
            sa.Column("outcome", sa.String(length=32), nullable=True),
            sa.Column("fence_token", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
            sa.Column("celery_task_id", sa.String(length=64), nullable=True),
            sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("duration_ms", sa.Integer(), nullable=True),
            sa.Column("error", sa.Text(), nullable=True),
            sa.Column("prompt_id", sa.String(length=64), nullable=True),
            sa.Column("llm_model", sa.String(length=128), nullable=True),
            sa.Column("tokens_in", sa.Integer(), nullable=True),
            sa.Column("tokens_out", sa.Integer(), nullable=True),
            sa.Column("cost_usd", sa.Numeric(12, 4), nullable=True),
            sa.Column("trace", JSONB(), nullable=True),
            sa.Column(
                "post_effect_applied", sa.Boolean(), nullable=False, server_default=sa.text("false")
            ),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
        )
        op.create_index(
            "ix_cairn_task_runs_tenant_project_state",
            "cairn_task_runs",
            ["tenant_id", "project_id", "state"],
        )
        op.create_index(
            "ix_cairn_task_runs_worker_state", "cairn_task_runs", ["worker_name", "state"]
        )

    if not _has_table("cairn_worker_backoff"):
        op.create_table(
            "cairn_worker_backoff",
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                primary_key=True,
            ),
            sa.Column("worker_name", sa.String(length=128), primary_key=True),
            sa.Column("kind", sa.String(length=16), primary_key=True),
            sa.Column("project_id", sa.String(length=36), primary_key=True, server_default=""),
            sa.Column("task_type", sa.String(length=16), primary_key=True, server_default=""),
            sa.Column("blocked_until", sa.DateTime(timezone=True), nullable=False),
            sa.CheckConstraint(
                "kind IN ('unhealthy','rejected')", name="ck_cairn_worker_backoff_kind"
            ),
        )
        op.create_index("ix_cairn_worker_backoff_until", "cairn_worker_backoff", ["blocked_until"])

    # Row-level security — tenant isolation, mirrors migration 002.
    for table in _RLS_TABLES:
        op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
        op.execute(f"""
            CREATE POLICY tenant_isolation ON "{table}"
            USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
            WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
            """)


def downgrade() -> None:
    for table in _DROP_ORDER:
        if _has_table(table):
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')
            op.drop_table(table)
