"""Seed default tenant for RLS — ensures DEFAULT_TENANT_ID exists.

Revision ID: 004
Revises: 003
Create Date: 2026-03-09

"""

from typing import Sequence, Union

from alembic import op

revision: str = "004"
down_revision: Union[str, None] = "003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

DEFAULT_TENANT_ID = "00000000-0000-0000-0000-000000000001"


def upgrade() -> None:
    op.execute(f"""
        INSERT INTO tenants (id, name, created_at, updated_at)
        VALUES ('{DEFAULT_TENANT_ID}', 'default', NOW(), NOW())
        ON CONFLICT (id) DO NOTHING
    """)


def downgrade() -> None:
    # Do not delete tenant — may have dependent data
    pass
