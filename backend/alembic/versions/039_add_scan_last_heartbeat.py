"""039 — Add last_heartbeat column to scans table

Revision ID: 039
Revises: 038_add_scan_email_column
Create Date: 2026-05-18

Adds nullable last_heartbeat (DateTime TZ) so the heartbeat loop
can track liveness independently of updated_at.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "039"
down_revision: Union[str, None] = "038"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("scans", sa.Column("last_heartbeat", sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "last_heartbeat")
