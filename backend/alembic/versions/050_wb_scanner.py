"""050 — Web Security Workbench Scanner persistence (WB-P5b).

Revision ID: 050
Revises: 049
Create Date: 2026-07-22

Adds tenant-scoped scanner tables:

* ``wb_scanner_tasks``       — scanner/crawler runs (crawl/audit/passive).
* ``wb_scanner_issue_links`` — task→finding associations (finding lives in the
  shared pipeline finding store; only the link is recorded here).

Both are tenant-scoped with PostgreSQL row-level security (``ENABLE`` + ``FORCE``
+ tenant-isolation policy), matching migrations 045/046/048/049. On SQLite
(smoke tests) RLS is skipped so upgrade/downgrade round-trips cleanly.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "050"
down_revision: str | None = "049"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TASKS = "wb_scanner_tasks"
_LINKS = "wb_scanner_issue_links"

_RLS_TABLES = (_TASKS, _LINKS)


def _json_type(is_postgres: bool) -> sa.types.TypeEngine:
    if is_postgres:
        return sa.dialects.postgresql.JSONB
    return sa.JSON


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    json_type = _json_type(is_postgres)

    op.create_table(
        _TASKS,
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
        sa.Column("kind", sa.String(16), nullable=False, server_default="passive"),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("config", json_type, nullable=True),
        sa.Column("checkpoint", json_type, nullable=True),
        sa.Column("requests_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_reason", sa.String(256), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_wb_scanner_task_project", _TASKS, ["tenant_id", "project_id", "status"])

    op.create_table(
        _LINKS,
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
            "task_id",
            sa.String(36),
            sa.ForeignKey("wb_scanner_tasks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("finding_id", sa.String(36), nullable=False),
        sa.Column("code", sa.String(64), nullable=False),
        sa.Column("confidence", sa.String(16), nullable=False, server_default="suspected"),
        sa.Column(
            "source_message_id",
            sa.String(36),
            sa.ForeignKey("wb_traffic_messages.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "task_id", "finding_id", name="uq_wb_scanner_issue_link"),
    )
    op.create_index("ix_wb_scanner_issue_task", _LINKS, ["tenant_id", "task_id"])

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

    op.drop_index("ix_wb_scanner_issue_task", table_name=_LINKS)
    op.drop_table(_LINKS)

    op.drop_index("ix_wb_scanner_task_project", table_name=_TASKS)
    op.drop_table(_TASKS)
