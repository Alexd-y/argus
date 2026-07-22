"""048 — Web Security Workbench Organizer (WB-P3c).

Revision ID: 048
Revises: 047
Create Date: 2026-07-22

Adds tenant-scoped Organizer tables:

* ``wb_organizer_collections`` — named folders grouping saved requests/notes.
* ``wb_organizer_items``       — saved request/note items (raw bytes + tags).

Both are tenant-scoped with PostgreSQL row-level security (``ENABLE`` + ``FORCE``
+ tenant-isolation policy), matching migrations 045/046. On SQLite (smoke tests)
RLS is skipped so the upgrade/downgrade round-trips cleanly.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "048"
down_revision: str | None = "047"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_COLLECTIONS = "wb_organizer_collections"
_ITEMS = "wb_organizer_items"

_RLS_TABLES = (_COLLECTIONS, _ITEMS)


def _json_type(is_postgres: bool) -> sa.types.TypeEngine:
    if is_postgres:
        return sa.dialects.postgresql.JSONB
    return sa.JSON


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    json_type = _json_type(is_postgres)

    op.create_table(
        _COLLECTIONS,
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
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "project_id", "name", name="uq_wb_org_collection_name"),
    )
    op.create_index("ix_wb_org_collection_project", _COLLECTIONS, ["tenant_id", "project_id"])

    op.create_table(
        _ITEMS,
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
            "collection_id",
            sa.String(36),
            sa.ForeignKey("wb_organizer_collections.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("title", sa.String(512), nullable=False),
        sa.Column("method", sa.String(32), nullable=True),
        sa.Column("host", sa.String(255), nullable=True),
        sa.Column("url", sa.Text(), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("tags", json_type, nullable=True),
        sa.Column("raw_request", sa.LargeBinary(), nullable=True),
        sa.Column("raw_response", sa.LargeBinary(), nullable=True),
        sa.Column(
            "source_message_id",
            sa.String(36),
            sa.ForeignKey("wb_traffic_messages.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_wb_org_item_collection", _ITEMS, ["tenant_id", "collection_id"])
    op.create_index("ix_wb_org_item_host", _ITEMS, ["tenant_id", "project_id", "host"])

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

    op.drop_index("ix_wb_org_item_host", table_name=_ITEMS)
    op.drop_index("ix_wb_org_item_collection", table_name=_ITEMS)
    op.drop_table(_ITEMS)

    op.drop_index("ix_wb_org_collection_project", table_name=_COLLECTIONS)
    op.drop_table(_COLLECTIONS)
