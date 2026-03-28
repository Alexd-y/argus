"""Findings — optional OWASP Top 10:2025 category (short id).

Adds ``findings.owasp_category`` (VARCHAR, nullable) with a CHECK constraint.

Allowed values: ``A01`` … ``A10`` only — canonical OWASP Top 10:2025 category codes
(stable ids; not slugs like ``broken_access_control``). See migration 011 / ``src/owasp_top10_2025.py``
for titles.

Revision ID: 011
Revises: 010
Create Date: 2026-03-26
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

from src.owasp_top10_2025 import findings_owasp_category_check_sql

revision: str = "011"
down_revision: str | None = "010"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FINDINGS_TABLE = "findings"
CK_NAME = "ck_findings_owasp_category"


def upgrade() -> None:
    op.add_column(
        FINDINGS_TABLE,
        sa.Column("owasp_category", sa.String(length=8), nullable=True),
    )
    op.create_check_constraint(CK_NAME, FINDINGS_TABLE, findings_owasp_category_check_sql())


def downgrade() -> None:
    op.drop_constraint(CK_NAME, FINDINGS_TABLE, type_="check")
    op.drop_column(FINDINGS_TABLE, "owasp_category")
