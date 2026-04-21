"""Per-tenant admin overrides: rate limit, scope blacklist, retention.

Revision ID: 025
Revises: 024
Create Date: 2026-04-22

Adds nullable columns on ``tenants`` for optional overrides (null = platform default).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "025"
down_revision: str | None = "024"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column("tenants", sa.Column("rate_limit_rpm", sa.Integer(), nullable=True))
    op.add_column(
        "tenants",
        sa.Column("scope_blacklist", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column("tenants", sa.Column("retention_days", sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column("tenants", "retention_days")
    op.drop_column("tenants", "scope_blacklist")
    op.drop_column("tenants", "rate_limit_rpm")
