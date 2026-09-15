"""064 — agent budget ledger tables (platform-hardening A, §7).

Revision ID: 064
Revises: 063
Create Date: 2026-09-11

Durable, authoritative budget accounting for agent/LLM work:

* ``agent_budget_scope`` — per-scope (tenant/scan/task) limits + reserved/used
  counters. Reservations lock these rows (``SELECT … FOR UPDATE``) for atomic
  cross-worker ``reserve``.
* ``agent_budget_reservation`` — one row per reservation with lifecycle state
  and lease expiry, indexed on ``(state, expires_at)`` for bounded reconciliation
  of stale holds.
* ``agent_budget_usage_event`` — one row per reservation (PK = reservation_id)
  so a settle can never double-charge, even across competing workers.

Idempotent: tables are only created when absent. No secrets are stored.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "064"
down_revision: str | None = "063"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return name in set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    if not _has_table("agent_budget_scope"):
        op.create_table(
            "agent_budget_scope",
            sa.Column("key", sa.String(length=128), primary_key=True),
            sa.Column("limit_tokens", sa.Float(), nullable=True),
            sa.Column("limit_cost", sa.Float(), nullable=True),
            sa.Column(
                "reserved_tokens", sa.BigInteger(), nullable=False, server_default=sa.text("0")
            ),
            sa.Column(
                "reserved_cost", sa.Float(), nullable=False, server_default=sa.text("0")
            ),
            sa.Column(
                "used_tokens", sa.BigInteger(), nullable=False, server_default=sa.text("0")
            ),
            sa.Column("used_cost", sa.Float(), nullable=False, server_default=sa.text("0")),
        )

    if not _has_table("agent_budget_reservation"):
        op.create_table(
            "agent_budget_reservation",
            sa.Column("reservation_id", sa.String(length=32), primary_key=True),
            sa.Column("scope_keys", sa.Text(), nullable=False),
            sa.Column("tokens", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
            sa.Column("cost_usd", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("state", sa.String(length=16), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index(
            "ix_agent_budget_reservation_state_expires",
            "agent_budget_reservation",
            ["state", "expires_at"],
        )

    if not _has_table("agent_budget_usage_event"):
        op.create_table(
            "agent_budget_usage_event",
            sa.Column("reservation_id", sa.String(length=32), primary_key=True),
            sa.Column("tokens", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
            sa.Column("cost_usd", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column(
                "estimated", sa.Boolean(), nullable=False, server_default=sa.text("false")
            ),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        )


def downgrade() -> None:
    if _has_table("agent_budget_usage_event"):
        op.drop_table("agent_budget_usage_event")
    if _has_table("agent_budget_reservation"):
        op.drop_index(
            "ix_agent_budget_reservation_state_expires",
            table_name="agent_budget_reservation",
        )
        op.drop_table("agent_budget_reservation")
    if _has_table("agent_budget_scope"):
        op.drop_table("agent_budget_scope")
