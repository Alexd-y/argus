"""041 — Admin password reset tokens table

Revision ID: 041
Revises: 040
Create Date: 2026-05-24

Adds admin_password_reset_tokens for email-verified password resets.
Each row stores a HMAC-SHA256 token hash + 6-digit OTP code, subject,
expiry, and tombstone (used_at).
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "041"
down_revision: Union[str, None] = "040"
branch_labels: Union[Sequence[str], None] = None
depends_on: Union[Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "admin_password_reset_tokens",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("otp_code", sa.String(6), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("ip_hash", sa.String(64), nullable=True),
    )
    op.create_index("ix_admin_reset_tokens_subject", "admin_password_reset_tokens", ["subject"])
    op.create_index("ix_admin_reset_tokens_expires_at", "admin_password_reset_tokens", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_admin_reset_tokens_expires_at", table_name="admin_password_reset_tokens")
    op.drop_index("ix_admin_reset_tokens_subject", table_name="admin_password_reset_tokens")
    op.drop_table("admin_password_reset_tokens")