"""051 — Web Security Workbench Intruder + Sessions persistence (WB-P4b / WB-P6b).

Revision ID: 051
Revises: 050
Create Date: 2026-07-23

Adds tenant-scoped tables for the Intruder engine and authenticated-session /
authorization-testing plane:

* ``wb_session_macros``     — login/session-setup macros (secret_ref placeholders
  only; no raw secrets).
* ``wb_session_principals`` — owner/attacker/anonymous identities (credentials
  referenced via ``secrets_ref``, never stored inline).
* ``wb_intruder_attacks``   — Intruder attack definitions/runs (byte-exact request
  template + payload-registry references; ``status='cancelled'`` = kill switch).
* ``wb_intruder_requests``  — per-request results (metadata-only; every attempt
  recorded, blocked attempts keep response columns NULL).

All four are tenant-scoped with PostgreSQL row-level security (``ENABLE`` +
``FORCE`` + tenant-isolation policy), matching migrations 045/046/048/049/050.
On SQLite (smoke tests) RLS is skipped so upgrade/downgrade round-trips cleanly.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "051"
down_revision: str | None = "050"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MACROS = "wb_session_macros"
_PRINCIPALS = "wb_session_principals"
_ATTACKS = "wb_intruder_attacks"
_REQUESTS = "wb_intruder_requests"

# RLS is applied to every new table; order matters for FK creation/drop.
_RLS_TABLES = (_MACROS, _PRINCIPALS, _ATTACKS, _REQUESTS)


def _json_type(is_postgres: bool) -> sa.types.TypeEngine:
    if is_postgres:
        return sa.dialects.postgresql.JSONB
    return sa.JSON


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"
    json_type = _json_type(is_postgres)

    # --- wb_session_macros -------------------------------------------------
    op.create_table(
        _MACROS,
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
        sa.Column("steps", json_type, nullable=True),
        sa.Column("match_rules", json_type, nullable=True),
        sa.Column("config", json_type, nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "project_id", "name", name="uq_wb_session_macro_name"),
    )
    op.create_index("ix_wb_session_macro_project", _MACROS, ["tenant_id", "project_id"])

    # --- wb_session_principals --------------------------------------------
    op.create_table(
        _PRINCIPALS,
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
        sa.Column("role", sa.String(16), nullable=False, server_default="owner"),
        sa.Column("secrets_ref", sa.String(256), nullable=True),
        sa.Column(
            "macro_id",
            sa.String(36),
            sa.ForeignKey("wb_session_macros.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("config", json_type, nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "project_id", "name", name="uq_wb_session_principal_name"),
    )
    op.create_index(
        "ix_wb_session_principal_project", _PRINCIPALS, ["tenant_id", "project_id", "role"]
    )

    # --- wb_intruder_attacks ----------------------------------------------
    op.create_table(
        _ATTACKS,
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
        sa.Column("attack_type", sa.String(16), nullable=False, server_default="sniper"),
        sa.Column("status", sa.String(16), nullable=False, server_default="queued"),
        sa.Column("raw_request_template", sa.LargeBinary(), nullable=False),
        sa.Column("positions", json_type, nullable=True),
        sa.Column("payload_config", json_type, nullable=True),
        sa.Column("config", json_type, nullable=True),
        sa.Column("checkpoint", json_type, nullable=True),
        sa.Column("requests_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("requests_completed", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_total", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_reason", sa.String(256), nullable=True),
        sa.Column("created_by_subject_hash", sa.String(64), nullable=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint("tenant_id", "project_id", "name", name="uq_wb_intruder_attack_name"),
    )
    op.create_index(
        "ix_wb_intruder_attack_project", _ATTACKS, ["tenant_id", "project_id", "status"]
    )

    # --- wb_intruder_requests ---------------------------------------------
    op.create_table(
        _REQUESTS,
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
            "attack_id",
            sa.String(36),
            sa.ForeignKey("wb_intruder_attacks.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("request_index", sa.Integer(), nullable=False),
        sa.Column("payload_label", sa.String(256), nullable=True),
        sa.Column("payload_index", sa.Integer(), nullable=True),
        sa.Column("forward_outcome", sa.String(16), nullable=False, server_default="forward"),
        sa.Column("block_reason", sa.String(64), nullable=True),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column("response_length", sa.Integer(), nullable=True),
        sa.Column("response_time_ms", sa.Integer(), nullable=True),
        sa.Column("response_sha256", sa.String(64), nullable=True),
        sa.Column("flagged", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("error_reason", sa.String(256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.UniqueConstraint(
            "tenant_id", "attack_id", "request_index", name="uq_wb_intruder_request_index"
        ),
    )
    op.create_index("ix_wb_intruder_request_attack", _REQUESTS, ["tenant_id", "attack_id"])
    op.create_index(
        "ix_wb_intruder_request_flagged", _REQUESTS, ["tenant_id", "attack_id", "flagged"]
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

    op.drop_index("ix_wb_intruder_request_flagged", table_name=_REQUESTS)
    op.drop_index("ix_wb_intruder_request_attack", table_name=_REQUESTS)
    op.drop_table(_REQUESTS)

    op.drop_index("ix_wb_intruder_attack_project", table_name=_ATTACKS)
    op.drop_table(_ATTACKS)

    op.drop_index("ix_wb_session_principal_project", table_name=_PRINCIPALS)
    op.drop_table(_PRINCIPALS)

    op.drop_index("ix_wb_session_macro_project", table_name=_MACROS)
    op.drop_table(_MACROS)
