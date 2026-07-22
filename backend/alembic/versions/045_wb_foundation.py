"""045 — Web Security Workbench foundation (WB-P1-FOUNDATION).

Revision ID: 045
Revises: 044
Create Date: 2026-07-22

Adds the tenant-scoped foundation tables for the Web Security Workbench:

* ``wb_projects``     — root aggregate for a workbench engagement.
* ``wb_scope_rules``  — persisted include/exclude scope rules per project.
* ``wb_eap``          — persisted signed Engagement Authorization Profile.

All three are tenant-scoped and get PostgreSQL row-level security
(``ENABLE`` + ``FORCE`` + tenant-isolation policy) matching the canonical
pattern used by migrations 026/027. On SQLite (smoke tests) RLS is skipped and
plain indexes are created so the upgrade/downgrade round-trips cleanly.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "045"
down_revision: str | None = "044"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PROJECTS = "wb_projects"
_SCOPE_RULES = "wb_scope_rules"
_EAP = "wb_eap"

_RLS_TABLES = (_PROJECTS, _SCOPE_RULES, _EAP)


def _json_type(is_postgres: bool) -> sa.types.TypeEngine:
    """JSONB on Postgres, generic JSON on SQLite (smoke round-trip)."""
    if is_postgres:
        return sa.dialects.postgresql.JSONB
    return sa.JSON


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    json_type = _json_type(is_postgres)

    op.create_table(
        _PROJECTS,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("status", sa.String(32), nullable=False, server_default="active"),
        sa.Column("config", json_type, nullable=True),
        sa.Column("secrets_ref", sa.String(256), nullable=True),
        sa.Column("created_by_subject_hash", sa.String(64), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
        sa.UniqueConstraint("tenant_id", "name", name="uq_wb_projects_tenant_name"),
    )
    op.create_index(
        "ix_wb_projects_tenant_status", _PROJECTS, ["tenant_id", "status"]
    )

    op.create_table(
        _SCOPE_RULES,
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
        sa.Column("kind", sa.String(16), nullable=False),
        sa.Column("pattern", sa.String(2048), nullable=False),
        sa.Column("deny", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("ports", json_type, nullable=True),
        sa.Column("note", sa.String(256), nullable=False, server_default=""),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
    )
    op.create_index(
        "ix_wb_scope_rules_project", _SCOPE_RULES, ["tenant_id", "project_id"]
    )

    op.create_table(
        _EAP,
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
        sa.Column("engagement_id", sa.String(128), nullable=False),
        sa.Column("signed_profile", json_type, nullable=False),
        sa.Column("signer_key_id", sa.String(16), nullable=True),
        sa.Column("status", sa.String(16), nullable=False, server_default="invalid"),
        sa.Column("expires", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()
        ),
    )
    op.create_index("ix_wb_eap_project", _EAP, ["tenant_id", "project_id"])
    op.create_index("ix_wb_eap_engagement", _EAP, ["tenant_id", "engagement_id"])

    if is_postgres:
        for table in _RLS_TABLES:
            op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(
                f"""
                CREATE POLICY tenant_isolation ON "{table}"
                    USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
                    WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
                """
            )


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        for table in _RLS_TABLES:
            op.execute(f'DROP POLICY IF EXISTS tenant_isolation ON "{table}"')
            op.execute(f'ALTER TABLE "{table}" NO FORCE ROW LEVEL SECURITY')
            op.execute(f'ALTER TABLE "{table}" DISABLE ROW LEVEL SECURITY')

    op.drop_index("ix_wb_eap_engagement", table_name=_EAP)
    op.drop_index("ix_wb_eap_project", table_name=_EAP)
    op.drop_table(_EAP)

    op.drop_index("ix_wb_scope_rules_project", table_name=_SCOPE_RULES)
    op.drop_table(_SCOPE_RULES)

    op.drop_index("ix_wb_projects_tenant_status", table_name=_PROJECTS)
    op.drop_table(_PROJECTS)
