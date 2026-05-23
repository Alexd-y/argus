"""040 — Report versioning, pentester assignment, compliance tags, share links

Revision ID: 040
Revises: 039_add_scan_last_heartbeat
Create Date: 2026-05-23

Adds version tracking, pentester assignment, compliance tags to reports,
and creates the report_share_links table for time-limited public access links.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "040"
down_revision: Union[str, None] = "039"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "reports",
        sa.Column("version", sa.Integer, nullable=False, server_default=sa.text("1")),
    )
    op.add_column(
        "reports",
        sa.Column("parent_report_id", sa.String(36), nullable=True),
    )
    op.add_column(
        "reports",
        sa.Column("assigned_to", sa.String(100), nullable=True),
    )
    op.add_column(
        "reports",
        sa.Column("compliance_tags", JSONB, nullable=True, server_default=sa.text("'[]'::jsonb")),
    )
    op.add_column(
        "reports",
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_foreign_key(
        "fk_reports_parent_report_id",
        "reports",
        "reports",
        ["parent_report_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_reports_parent_report_id",
        "reports",
        ["parent_report_id"],
    )

    op.create_table(
        "report_share_links",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("report_id", sa.String(36), sa.ForeignKey("reports.id", ondelete="CASCADE"), nullable=False),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token", sa.String(64), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("viewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("view_count", sa.Integer, nullable=False, server_default=sa.text("0")),
    )
    op.create_index(
        "ix_report_share_links_token",
        "report_share_links",
        ["token"],
        unique=True,
    )
    op.create_index(
        "ix_report_share_links_report_id",
        "report_share_links",
        ["report_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_report_share_links_report_id", table_name="report_share_links")
    op.drop_index("ix_report_share_links_token", table_name="report_share_links")
    op.drop_table("report_share_links")

    op.drop_index("ix_reports_parent_report_id", table_name="reports")
    op.drop_constraint("fk_reports_parent_report_id", "reports", type_="foreignkey")

    op.drop_column("reports", "updated_at")
    op.drop_column("reports", "compliance_tags")
    op.drop_column("reports", "assigned_to")
    op.drop_column("reports", "parent_report_id")
    op.drop_column("reports", "version")