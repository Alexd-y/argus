"""Findings — optional proof_of_concept JSONB (PoC enrichment).

Revision ID: 010
Revises: 009
Create Date: 2026-03-25
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "010"
down_revision: str | None = "009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FINDINGS_TABLE = "findings"


def upgrade() -> None:
    op.add_column(
        FINDINGS_TABLE,
        sa.Column("proof_of_concept", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    op.drop_column(FINDINGS_TABLE, "proof_of_concept")
