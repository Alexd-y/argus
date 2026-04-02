"""Findings — keep server default on confidence for INSERTs that omit the column.

013 added ``confidence`` NOT NULL then removed server_default; workers that bulk-insert
without the column (or older images) then hit NOT NULL violations. Restore DB default.

Revision ID: 014
Revises: 013
Create Date: 2026-03-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "014"
down_revision: str | None = "013"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FINDINGS_TABLE = "findings"


def upgrade() -> None:
    op.alter_column(
        FINDINGS_TABLE,
        "confidence",
        server_default=sa.text("'likely'"),
        existing_type=sa.String(length=20),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.alter_column(
        FINDINGS_TABLE,
        "confidence",
        server_default=None,
        existing_type=sa.String(length=20),
        existing_nullable=False,
    )
