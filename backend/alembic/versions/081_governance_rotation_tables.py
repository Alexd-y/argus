"""081 — governance + rotation tables: engagements, approvals, llm_rotation_states.

Three tenant-scoped tables with FORCE row-level security (consistent with the other
tenant tables):

* ``engagements`` — signed-engagement authorization envelope (WP A/D). Append-only by
  convention: a revocation flips ``revoked`` rather than deleting.
* ``approvals`` — human-in-the-loop approval queue (WP D). Fail-closed: an action is
  not executable until ``status='approved'``.
* ``llm_rotation_states`` — persisted multi-LLM rotation cursor (WP C).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "081"
down_revision: str | None = "080"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_POLICY = "tenant_isolation"
_JSON = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")
_TABLES = ("governance_engagements", "approvals", "llm_rotation_states")


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _enable_rls(table: str) -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(f'DROP POLICY IF EXISTS {_POLICY} ON "{table}"')
    op.execute(f"""
        CREATE POLICY {_POLICY} ON "{table}"
            USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
            WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
        """)


def upgrade() -> None:
    if not _has_table("governance_engagements"):
        op.create_table(
            "governance_engagements",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("allowed_targets", _JSON, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("allowed_tenants", _JSON, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("allowed_actions", _JSON, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("window_start", sa.DateTime(timezone=True), nullable=True),
            sa.Column("window_end", sa.DateTime(timezone=True), nullable=True),
            sa.Column("max_rate_per_target", sa.Integer(), nullable=True),
            sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
            sa.Column("signature", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )
        op.create_index("ix_governance_engagements_tenant", "governance_engagements", ["tenant_id"])
    _enable_rls("governance_engagements")

    if not _has_table("approvals"):
        op.create_table(
            "approvals",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "scan_id",
                sa.String(length=36),
                sa.ForeignKey("scans.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column("action", sa.String(length=128), nullable=False),
            sa.Column(
                "target", sa.String(length=512), nullable=False, server_default=sa.text("''")
            ),
            sa.Column("reason", sa.Text(), nullable=True),
            sa.Column(
                "status", sa.String(length=20), nullable=False, server_default=sa.text("'pending'")
            ),
            sa.Column("decided_by", sa.String(length=255), nullable=True),
            sa.Column("decision_reason", sa.Text(), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        )
        op.create_index("ix_approvals_tenant_status", "approvals", ["tenant_id", "status"])
    _enable_rls("approvals")

    if not _has_table("llm_rotation_states"):
        op.create_table(
            "llm_rotation_states",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "scan_id",
                sa.String(length=36),
                sa.ForeignKey("scans.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column(
                "role", sa.String(length=64), nullable=False, server_default=sa.text("'report'")
            ),
            sa.Column("profile_ids", _JSON, nullable=False, server_default=sa.text("'[]'")),
            sa.Column("cursor", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("excluded", _JSON, nullable=False, server_default=sa.text("'[]'")),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
            sa.Column(
                "updated_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )
        op.create_index(
            "ix_llm_rotation_states_scope",
            "llm_rotation_states",
            ["tenant_id", "scan_id", "role"],
        )
    _enable_rls("llm_rotation_states")


def downgrade() -> None:
    bind = op.get_bind()
    is_pg = bind.dialect.name == "postgresql"
    for table in _TABLES:
        if is_pg:
            op.execute(f'DROP POLICY IF EXISTS {_POLICY} ON "{table}"')
    if _has_table("llm_rotation_states"):
        op.drop_index("ix_llm_rotation_states_scope", table_name="llm_rotation_states")
        op.drop_table("llm_rotation_states")
    if _has_table("approvals"):
        op.drop_index("ix_approvals_tenant_status", table_name="approvals")
        op.drop_table("approvals")
    if _has_table("governance_engagements"):
        op.drop_index("ix_governance_engagements_tenant", table_name="governance_engagements")
        op.drop_table("governance_engagements")
