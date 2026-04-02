"""Add scans.scan_mode and findings.dedup_status columns.

Revision ID: 016
Revises: 015
"""

from alembic import op
import sqlalchemy as sa


revision: str = "016"
down_revision: str | None = "015"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.execute(
        "ALTER TABLE scans ADD COLUMN IF NOT EXISTS scan_mode VARCHAR(20) NOT NULL DEFAULT 'standard'"
    )
    op.execute(
        "ALTER TABLE findings ADD COLUMN IF NOT EXISTS dedup_status VARCHAR(20) DEFAULT 'unchecked'"
    )


def downgrade() -> None:
    op.execute("ALTER TABLE scans DROP COLUMN IF EXISTS scan_mode")
    op.execute("ALTER TABLE findings DROP COLUMN IF EXISTS dedup_status")
