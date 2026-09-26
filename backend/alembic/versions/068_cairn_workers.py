"""068 — DB-backed Cairn worker configuration (§12.2).

Workers as rows instead of dispatch.yaml. Secrets stay in ProviderConfig/env.
Tenant-scoped with FORCE RLS, conventions per migration 066/067.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "068"
down_revision: str | None = "067"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return name in set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    if not _has_table("cairn_workers"):
        op.create_table(
            "cairn_workers",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("name", sa.String(length=128), nullable=False),
            sa.Column("type", sa.String(length=32), nullable=False, server_default="wrb"),
            sa.Column("task_types", JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")),
            sa.Column("max_running", sa.Integer(), nullable=False, server_default=sa.text("1")),
            sa.Column("priority", sa.Integer(), nullable=False, server_default=sa.text("100")),
            sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
            sa.Column("provider_config_id", sa.String(length=36), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.UniqueConstraint("tenant_id", "name", name="uq_cairn_workers_tenant_name"),
        )
        op.execute("ALTER TABLE cairn_workers ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE cairn_workers FORCE ROW LEVEL SECURITY")
        op.execute("""
            CREATE POLICY tenant_isolation ON cairn_workers
            USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
            WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
            """)


def downgrade() -> None:
    if _has_table("cairn_workers"):
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON cairn_workers")
        op.execute("ALTER TABLE cairn_workers DISABLE ROW LEVEL SECURITY")
        op.drop_table("cairn_workers")
