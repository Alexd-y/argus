"""Findings — confidence, evidence_type, evidence_refs, reproducible_steps, applicability_notes (T4).

Revision ID: 013
Revises: 012
Create Date: 2026-03-29
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "013"
down_revision: str | None = "012"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FINDINGS_TABLE = "findings"


def upgrade() -> None:
    op.add_column(
        FINDINGS_TABLE,
        sa.Column("confidence", sa.String(length=20), nullable=False, server_default="likely"),
    )
    op.add_column(
        FINDINGS_TABLE,
        sa.Column("evidence_type", sa.String(length=40), nullable=True),
    )
    op.add_column(
        FINDINGS_TABLE,
        sa.Column(
            "evidence_refs",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
    )
    op.add_column(
        FINDINGS_TABLE,
        sa.Column("reproducible_steps", sa.Text(), nullable=True),
    )
    op.add_column(
        FINDINGS_TABLE,
        sa.Column("applicability_notes", sa.Text(), nullable=True),
    )
    op.alter_column(FINDINGS_TABLE, "confidence", server_default=None)


def downgrade() -> None:
    op.drop_column(FINDINGS_TABLE, "applicability_notes")
    op.drop_column(FINDINGS_TABLE, "reproducible_steps")
    op.drop_column(FINDINGS_TABLE, "evidence_refs")
    op.drop_column(FINDINGS_TABLE, "evidence_type")
    op.drop_column(FINDINGS_TABLE, "confidence")
