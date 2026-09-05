"""062 — scan_quotas table (per-tenant monthly scan quota + bonus credits).

Revision ID: 062
Revises: 061
Create Date: 2026-09-06

Block 4.6: tracks a tenant's included scans per monthly period plus purchasable
bonus credits, backing GET /api/v1/quota and the buy-more flow. Idempotent:
the table is only created when absent.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "062"
down_revision: str | None = "061"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return name in set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    if _has_table("scan_quotas"):
        return
    op.create_table(
        "scan_quotas",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(length=36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("tier", sa.String(length=20), nullable=False, server_default="free"),
        sa.Column("period_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("period_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_this_period", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column("bonus_credits", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "bonus_used_this_period", sa.Integer(), nullable=False, server_default=sa.text("0")
        ),
        sa.Column("stripe_customer_id", sa.String(length=64), nullable=True),
        sa.Column("stripe_subscription_id", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scan_quotas_tenant_id", "scan_quotas", ["tenant_id"])


def downgrade() -> None:
    if _has_table("scan_quotas"):
        op.drop_index("ix_scan_quotas_tenant_id", table_name="scan_quotas")
        op.drop_table("scan_quotas")
