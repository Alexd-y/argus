"""067 — Cairn pentest directives (Phase 14).

Stores generated pentest directives (typed, focused next steps) linked to a Cairn
project. Tenant-scoped with FORCE RLS, same conventions as migration 066.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision: str = "067"
down_revision: str | None = "066"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _has_table(name: str) -> bool:
    bind = op.get_bind()
    return name in set(sa.inspect(bind).get_table_names())


def upgrade() -> None:
    if not _has_table("cairn_directives"):
        op.create_table(
            "cairn_directives",
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column("ref", sa.String(length=16), nullable=False),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "project_id",
                sa.String(length=36),
                sa.ForeignKey("cairn_projects.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("scan_id", sa.String(length=36), nullable=True),
            sa.Column("kind", sa.String(length=32), nullable=False),
            sa.Column("title", sa.String(length=200), nullable=False),
            sa.Column("directive_text", sa.Text(), nullable=False),
            sa.Column("focus", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("success_criterion", sa.Text(), nullable=False, server_default=""),
            sa.Column(
                "proof_requirement",
                sa.String(length=32),
                nullable=False,
                server_default="tool_output",
            ),
            sa.Column(
                "intrusiveness", sa.String(length=32), nullable=False, server_default="active_safe"
            ),
            sa.Column("priority_score", sa.Float(), nullable=False, server_default=sa.text("0")),
            sa.Column("priority_rationale", sa.Text(), nullable=True),
            sa.Column(
                "scope_guard", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
            ),
            sa.Column("basis", JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")),
            sa.Column("status", sa.String(length=16), nullable=False, server_default="proposed"),
            sa.Column(
                "intent_id",
                sa.String(length=36),
                sa.ForeignKey("cairn_intents.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("outcome_fact_ref", sa.String(length=16), nullable=True),
            sa.Column("llm_provenance", JSONB(), nullable=True),
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
            sa.UniqueConstraint("project_id", "ref", name="uq_cairn_directives_project_ref"),
        )
        op.create_index(
            "ix_cairn_directives_scan_status",
            "cairn_directives",
            ["tenant_id", "scan_id", "status"],
        )
        op.create_index(
            "ix_cairn_directives_priority", "cairn_directives", ["tenant_id", "priority_score"]
        )
        op.execute("ALTER TABLE cairn_directives ENABLE ROW LEVEL SECURITY")
        op.execute("ALTER TABLE cairn_directives FORCE ROW LEVEL SECURITY")
        op.execute("""
            CREATE POLICY tenant_isolation ON cairn_directives
            USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
            WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
            """)


def downgrade() -> None:
    if _has_table("cairn_directives"):
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON cairn_directives")
        op.execute("ALTER TABLE cairn_directives DISABLE ROW LEVEL SECURITY")
        op.drop_table("cairn_directives")
