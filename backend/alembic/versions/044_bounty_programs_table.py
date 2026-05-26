"""044 — BountyProgram table for bug bounty planning module.

Revision ID: 044
Revises: 043
Create Date: 2026-05-27

Adds bounty_programs table for storing bug bounty scope configurations.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "044"
down_revision: str | None = "043"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "bounty_programs"


def upgrade() -> None:
    op.create_table(
        TABLE,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("platform", sa.String(32), nullable=False, server_default="private"),
        sa.Column("scope_config", sa.dialects.postgresql.JSONB, nullable=True),
        sa.Column("reward_range", sa.String(128), nullable=True),
        sa.Column("status", sa.String(20), nullable=False, server_default="draft"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_bounty_programs_tenant_id", TABLE, ["tenant_id"])


def downgrade() -> None:
    op.drop_index("ix_bounty_programs_tenant_id", table_name=TABLE)
    op.drop_table(TABLE)