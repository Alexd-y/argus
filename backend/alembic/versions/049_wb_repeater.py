"""049 — Web Security Workbench Repeater persistence (WB-P3b-2).

Revision ID: 049
Revises: 048
Create Date: 2026-07-22

Adds tenant-scoped Repeater tables:

* ``wb_repeater_tabs``      — saved editable request slots (byte-exact raw).
* ``wb_repeater_exchanges`` — recorded replay attempts (forwarded or blocked).

Both are tenant-scoped with PostgreSQL row-level security (``ENABLE`` + ``FORCE``
+ tenant-isolation policy), matching migrations 045/046/048. On SQLite (smoke
tests) RLS is skipped so the upgrade/downgrade round-trips cleanly.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "049"
down_revision: str | None = "048"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABS = "wb_repeater_tabs"
_EXCHANGES = "wb_repeater_exchanges"

_RLS_TABLES = (_TABS, _EXCHANGES)


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    op.create_table(
        _TABS,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            sa.String(36),
            sa.ForeignKey("wb_projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("raw_request", sa.LargeBinary(), nullable=False),
        sa.Column("scheme", sa.String(8), nullable=True),
        sa.Column("host", sa.String(255), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_wb_repeater_tab_project", _TABS, ["tenant_id", "project_id"])

    op.create_table(
        _EXCHANGES,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            sa.String(36),
            sa.ForeignKey("wb_projects.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "tab_id",
            sa.String(36),
            sa.ForeignKey("wb_repeater_tabs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("raw_request", sa.LargeBinary(), nullable=False),
        sa.Column("forward_outcome", sa.String(16), nullable=False),
        sa.Column("block_reason", sa.String(64), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("raw_response", sa.LargeBinary(), nullable=True),
        sa.Column("response_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_wb_repeater_exchange_tab", _EXCHANGES, ["tenant_id", "tab_id", "created_at"]
    )

    if is_postgres:
        for table in _RLS_TABLES:
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(f"""
                CREATE POLICY tenant_isolation ON "{table}"
                    USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
                    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
                """)


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        for table in _RLS_TABLES:
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')

    op.drop_index("ix_wb_repeater_exchange_tab", table_name=_EXCHANGES)
    op.drop_table(_EXCHANGES)

    op.drop_index("ix_wb_repeater_tab_project", table_name=_TABS)
    op.drop_table(_TABS)
