"""054 — execution mode, LAB scope manifests, LAB leases (+ RLS).

Revision ID: 054
Revises: 053
Create Date: 2026-08-15

Stage A foundation for unified AI/RAG/LAB architecture.
``lab_unrestricted`` never disables RLS or tenant filters.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "054"
down_revision: str | None = "053"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES: tuple[str, ...] = (
    "lab_scope_manifests",
    "lab_execution_leases",
    "engagement_execution_modes",
)


def upgrade() -> None:
    bind = op.get_bind()
    json_type = postgresql.JSONB() if bind.dialect.name == "postgresql" else sa.JSON()

    op.create_table(
        "engagement_execution_modes",
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id", ondelete="CASCADE"), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("mode", sa.String(32), nullable=False, server_default="production"),
        sa.Column("first_execution_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
    )
    op.create_index(
        "ix_engagement_execution_modes_tenant",
        "engagement_execution_modes",
        ["tenant_id", "mode"],
    )

    op.create_table(
        "lab_scope_manifests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("mode", sa.String(32), nullable=False, server_default="lab_unrestricted"),
        sa.Column("payload", json_type, nullable=False),
        sa.Column("signature", sa.String(128), nullable=True),
        sa.Column("capture_full", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_by", sa.String(36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_lab_scope_manifests_tenant_engagement",
        "lab_scope_manifests",
        ["tenant_id", "engagement_id"],
    )
    op.create_index("ix_lab_scope_manifests_expires", "lab_scope_manifests", ["expires_at"])

    op.create_table(
        "lab_execution_leases",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("tenant_id", sa.String(36), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("engagement_id", sa.String(36), sa.ForeignKey("engagements.id", ondelete="CASCADE"), nullable=False),
        sa.Column("manifest_id", sa.String(36), sa.ForeignKey("lab_scope_manifests.id", ondelete="CASCADE"), nullable=False),
        sa.Column("mode", sa.String(32), nullable=False, server_default="lab_unrestricted"),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("boundary_proof", sa.String(128), nullable=False),
        sa.Column("capture_full", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("k8s_namespace", sa.String(253), nullable=True),
        sa.Column("payload", json_type, nullable=True),
        sa.Column("issued_at", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.Text(), nullable=True),
    )
    op.create_index(
        "ix_lab_execution_leases_tenant_engagement",
        "lab_execution_leases",
        ["tenant_id", "engagement_id"],
    )
    op.create_index(
        "ix_lab_execution_leases_status",
        "lab_execution_leases",
        ["status", "expires_at"],
    )

    if bind.dialect.name == "postgresql":
        for table in _TENANT_TABLES:
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(
                f"""
                CREATE POLICY tenant_isolation ON "{table}"
                USING (tenant_id = current_setting('app.current_tenant_id', true))
                WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true))
                """
            )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        for table in _TENANT_TABLES:
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')

    op.drop_table("lab_execution_leases")
    op.drop_table("lab_scope_manifests")
    op.drop_table("engagement_execution_modes")
