"""Reports — tier, generation status, template/prompt versions, error message, JSONB extras, indexes.

Revision ID: 009
Revises: 008
Create Date: 2026-03-20

Backward-compatible: new columns are NOT NULL only where server_default is set; JSONB columns nullable.

tier and generation_status keep a permanent PostgreSQL server_default ('midgard', 'ready') so raw SQL,
legacy writers, and out-of-order deploys still get valid values without requiring every INSERT to set them.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "009"
down_revision: str | None = "008"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

REPORTS_TABLE = "reports"


def upgrade() -> None:
    op.add_column(
        REPORTS_TABLE,
        sa.Column("tier", sa.String(32), nullable=False, server_default="midgard"),
    )
    op.add_column(
        REPORTS_TABLE,
        sa.Column("generation_status", sa.String(32), nullable=False, server_default="ready"),
    )
    op.add_column(
        REPORTS_TABLE,
        sa.Column("template_version", sa.String(64), nullable=True),
    )
    op.add_column(
        REPORTS_TABLE,
        sa.Column("prompt_version", sa.String(64), nullable=True),
    )
    op.add_column(
        REPORTS_TABLE,
        sa.Column("last_error_message", sa.Text(), nullable=True),
    )
    op.add_column(
        REPORTS_TABLE,
        sa.Column("requested_formats", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )
    op.add_column(
        REPORTS_TABLE,
        sa.Column("report_metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )

    op.create_index(
        "ix_reports_tenant_target_created",
        REPORTS_TABLE,
        ["tenant_id", "target", "created_at"],
    )
    op.create_index(
        "ix_reports_scan_tier",
        REPORTS_TABLE,
        ["scan_id", "tier"],
    )


def downgrade() -> None:
    op.drop_index("ix_reports_scan_tier", table_name=REPORTS_TABLE)
    op.drop_index("ix_reports_tenant_target_created", table_name=REPORTS_TABLE)

    op.drop_column(REPORTS_TABLE, "report_metadata")
    op.drop_column(REPORTS_TABLE, "requested_formats")
    op.drop_column(REPORTS_TABLE, "last_error_message")
    op.drop_column(REPORTS_TABLE, "prompt_version")
    op.drop_column(REPORTS_TABLE, "template_version")
    op.drop_column(REPORTS_TABLE, "generation_status")
    op.drop_column(REPORTS_TABLE, "tier")
