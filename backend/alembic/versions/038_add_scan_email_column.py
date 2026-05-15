"""038 — Add email column to scans table

Revision ID: 038
Revises: 037_rls_hardening_phase234
Create Date: 2026-05-15

Adds a nullable email (VARCHAR 320) column so scan creation stores
the operator's contact from the frontend.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "038"
down_revision: Union[str, None] = "037"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("email", sa.String(320), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "email")
