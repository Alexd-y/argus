"""Widen report_objects.format for Valhalla auxiliary CSV (VHL-005).

``valhalla_sections.csv`` exceeds VARCHAR(20).

Revision ID: 012
Revises: 011
Create Date: 2026-03-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "012"
down_revision: str | None = "011"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE = "report_objects"
COL = "format"


def upgrade() -> None:
    op.alter_column(
        TABLE,
        COL,
        existing_type=sa.String(length=20),
        type_=sa.String(length=48),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        TABLE,
        COL,
        existing_type=sa.String(length=48),
        type_=sa.String(length=20),
        existing_nullable=False,
    )
