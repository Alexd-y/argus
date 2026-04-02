"""Add findings.adversarial_score and scans.cost_summary.

ENH-003: adversarial_score (Float / DOUBLE PRECISION, nullable).
ENH-008: cost_summary (JSONB, nullable).

Uses IF NOT EXISTS so re-applying the DDL is safe outside Alembic revision order.

Revision ID: 015
Revises: 014
Create Date: 2026-04-02
"""

from collections.abc import Sequence

from alembic import op

revision: str = "015"
down_revision: str | None = "014"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # DOUBLE PRECISION matches SQLAlchemy Float on PostgreSQL (same as findings.cvss).
    op.execute(
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS adversarial_score DOUBLE PRECISION"
    )
    op.execute("ALTER TABLE scans ADD COLUMN IF NOT EXISTS cost_summary JSONB")


def downgrade() -> None:
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS adversarial_score")
    op.execute("ALTER TABLE scans DROP COLUMN IF EXISTS cost_summary")
