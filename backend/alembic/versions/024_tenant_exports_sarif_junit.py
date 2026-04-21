"""T04 — Per-tenant opt-in for SARIF/JUnit findings export API.

Revision ID: 024
Revises: 023
Create Date: 2026-04-21

Adds ``tenants.exports_sarif_junit_enabled`` (boolean, default false).
When false, export endpoints return generic 404 (no feature probe).
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision: str = "024"
down_revision: str | None = "023"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "exports_sarif_junit_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("tenants", "exports_sarif_junit_enabled")
