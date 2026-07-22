"""046 — Web Security Workbench proxy data-plane (WB-P2a-2).

Revision ID: 046
Revises: 045
Create Date: 2026-07-22

Adds the tenant-scoped proxy persistence tables:

* ``wb_proxy_listeners``       — intercepting-proxy listener + per-listener CA.
* ``wb_traffic_messages``      — captured request/response pairs.
* ``wb_traffic_body_artifacts``— out-of-line HTTP bodies (inline / s3 / dropped).
* ``wb_message_revisions``     — raw-head edit revisions (Repeater/manual).

All four are tenant-scoped with PostgreSQL row-level security (``ENABLE`` +
``FORCE`` + tenant-isolation policy), matching migration 045. On SQLite (smoke
tests) RLS is skipped so the upgrade/downgrade round-trips cleanly.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "046"
down_revision: str | None = "045"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_LISTENERS = "wb_proxy_listeners"
_MESSAGES = "wb_traffic_messages"
_BODIES = "wb_traffic_body_artifacts"
_REVISIONS = "wb_message_revisions"

_RLS_TABLES = (_LISTENERS, _MESSAGES, _BODIES, _REVISIONS)


def _json_type(is_postgres: bool) -> sa.types.TypeEngine:
    if is_postgres:
        return sa.dialects.postgresql.JSONB
    return sa.JSON


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    json_type = _json_type(is_postgres)

    op.create_table(
        _LISTENERS,
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
        sa.Column("host", sa.String(255), nullable=False, server_default="127.0.0.1"),
        sa.Column("port", sa.Integer(), nullable=False, server_default="8080"),
        sa.Column("status", sa.String(16), nullable=False, server_default="disabled"),
        sa.Column(
            "intercept_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.false(),
        ),
        sa.Column("intercept_rules", json_type, nullable=True),
        sa.Column("config", json_type, nullable=True),
        sa.Column("ca_cert_pem", sa.Text(), nullable=True),
        sa.Column("ca_secrets_ref", sa.String(256), nullable=True),
        sa.Column("ca_fingerprint", sa.String(64), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "project_id", "name", name="uq_wb_listeners_project_name"),
    )
    op.create_index("ix_wb_listeners_project", _LISTENERS, ["tenant_id", "project_id"])

    op.create_table(
        _MESSAGES,
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
            "listener_id",
            sa.String(36),
            sa.ForeignKey("wb_proxy_listeners.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("source", sa.String(16), nullable=False, server_default="proxy"),
        sa.Column("method", sa.String(32), nullable=False),
        sa.Column("scheme", sa.String(8), nullable=False, server_default="https"),
        sa.Column("host", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default="443"),
        sa.Column("path", sa.Text(), nullable=False, server_default="/"),
        sa.Column("query", sa.Text(), nullable=True),
        sa.Column("http_version", sa.String(16), nullable=False, server_default="HTTP/1.1"),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("request_headers", json_type, nullable=True),
        sa.Column("response_headers", json_type, nullable=True),
        sa.Column("request_body_id", sa.String(36), nullable=True),
        sa.Column("response_body_id", sa.String(36), nullable=True),
        sa.Column("forward_outcome", sa.String(16), nullable=False, server_default="forward"),
        sa.Column("block_reason", sa.String(64), nullable=True),
        sa.Column("in_scope", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("tags", json_type, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_wb_traffic_project_created",
        _MESSAGES,
        ["tenant_id", "project_id", "created_at"],
    )
    op.create_index("ix_wb_traffic_host", _MESSAGES, ["tenant_id", "host"])

    op.create_table(
        _BODIES,
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
            "message_id",
            sa.String(36),
            sa.ForeignKey("wb_traffic_messages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("direction", sa.String(8), nullable=False),
        sa.Column("storage_backend", sa.String(8), nullable=False),
        sa.Column("inline_bytes", sa.LargeBinary(), nullable=True),
        sa.Column("object_key", sa.String(1024), nullable=True),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("content_type", sa.String(256), nullable=True),
        sa.Column("truncated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_wb_body_message", _BODIES, ["tenant_id", "message_id"])

    op.create_table(
        _REVISIONS,
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
            "message_id",
            sa.String(36),
            sa.ForeignKey("wb_traffic_messages.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("revision_no", sa.Integer(), nullable=False),
        sa.Column("editor_subject_hash", sa.String(64), nullable=True),
        sa.Column("raw_head", sa.Text(), nullable=False),
        sa.Column("note", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "message_id", "revision_no", name="uq_wb_revision_no"),
    )
    op.create_index("ix_wb_revision_message", _REVISIONS, ["tenant_id", "message_id"])

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

    op.drop_index("ix_wb_revision_message", table_name=_REVISIONS)
    op.drop_table(_REVISIONS)

    op.drop_index("ix_wb_body_message", table_name=_BODIES)
    op.drop_table(_BODIES)

    op.drop_index("ix_wb_traffic_host", table_name=_MESSAGES)
    op.drop_index("ix_wb_traffic_project_created", table_name=_MESSAGES)
    op.drop_table(_MESSAGES)

    op.drop_index("ix_wb_listeners_project", table_name=_LISTENERS)
    op.drop_table(_LISTENERS)
