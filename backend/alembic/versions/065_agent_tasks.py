"""065 — durable agent-task store + transactional outbox (platform-hardening A, §6).

Revision ID: 065
Revises: 064
Create Date: 2026-09-11

* ``agent_task`` — durable logical task with claim/lease/fencing columns.
  ``idempotency_key`` is unique so re-enqueue is a no-op. Indexed on
  ``(state, created_at)`` for the ``FOR UPDATE SKIP LOCKED`` claim scan.
* ``agent_task_outbox`` — transactional outbox: written in the same transaction
  as the task row so a relay can reconcile "saved but not dispatched" messages.

Idempotent: tables are only created when absent. Celery payloads reference the
``task_id`` only; no secrets/evidence are stored in these tables.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "065"
down_revision: str | None = "064"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return name in set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    if not _has_table("agent_task"):
        op.create_table(
            "agent_task",
            sa.Column("task_id", sa.String(length=36), primary_key=True),
            sa.Column("tenant_id", sa.String(length=36), nullable=False),
            sa.Column("scan_id", sa.String(length=36), nullable=False),
            sa.Column("phase", sa.String(length=64), nullable=False),
            sa.Column("agent_role", sa.String(length=64), nullable=False),
            sa.Column("idempotency_key", sa.String(length=64), nullable=False, unique=True),
            sa.Column("state", sa.String(length=16), nullable=False),
            sa.Column("attempts", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column(
                "max_attempts", sa.Integer(), nullable=False, server_default=sa.text("3")
            ),
            sa.Column(
                "fencing_token", sa.BigInteger(), nullable=False, server_default=sa.text("0")
            ),
            sa.Column("worker_id", sa.String(length=64), nullable=False, server_default=""),
            sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column("payload", sa.Text(), nullable=False, server_default="{}"),
            sa.Column("result_ref", sa.Text(), nullable=True),
            sa.Column("last_error", sa.Text(), nullable=False, server_default=""),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_agent_task_state_created", "agent_task", ["state", "created_at"]
        )
        op.create_index("ix_agent_task_scan", "agent_task", ["scan_id"])

    if not _has_table("agent_task_outbox"):
        op.create_table(
            "agent_task_outbox",
            sa.Column("id", sa.String(length=32), primary_key=True),
            sa.Column("task_id", sa.String(length=36), nullable=False),
            sa.Column(
                "dispatched", sa.Boolean(), nullable=False, server_default=sa.text("false")
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )
        op.create_index(
            "ix_agent_task_outbox_undispatched",
            "agent_task_outbox",
            ["dispatched", "created_at"],
        )


def downgrade() -> None:
    if _has_table("agent_task_outbox"):
        op.drop_index("ix_agent_task_outbox_undispatched", table_name="agent_task_outbox")
        op.drop_table("agent_task_outbox")
    if _has_table("agent_task"):
        op.drop_index("ix_agent_task_scan", table_name="agent_task")
        op.drop_index("ix_agent_task_state_created", table_name="agent_task")
        op.drop_table("agent_task")
