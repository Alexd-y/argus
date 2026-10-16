"""077 — llm_invocation_outcomes: LLM proposal → arbiter verdict link (Wave 5, R-9.2).

One row per finding an LLM proposal produced, carrying the model-proposed tier,
the wave-1 evidence-arbiter tier, and a derived outcome label. This is the
objective "was the model right" signal the measurement stage (R-9.7) needs.
Tenant-scoped with FORCE row-level security, consistent with the other tenant
tables. finding_id / invocation_id / scan_id are soft references (no FK) so the
analytics write stays decoupled from the findings-persistence transaction.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "077"
down_revision: str | None = "076"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "llm_invocation_outcomes"
_POLICY = "tenant_isolation"


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def upgrade() -> None:
    if not _has_table(_TABLE):
        op.create_table(
            _TABLE,
            sa.Column("id", sa.String(length=36), primary_key=True),
            sa.Column(
                "tenant_id",
                sa.String(length=36),
                sa.ForeignKey("tenants.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column("scan_id", sa.String(length=36), nullable=True),
            sa.Column("phase", sa.String(length=32), nullable=True),
            sa.Column("task", sa.String(length=32), nullable=True),
            sa.Column("invocation_id", sa.String(length=36), nullable=True),
            sa.Column("finding_id", sa.String(length=36), nullable=True),
            sa.Column("vuln_class", sa.String(length=64), nullable=True),
            sa.Column("model_tier", sa.Integer(), nullable=True),
            sa.Column("arbiter_tier", sa.Integer(), nullable=True),
            sa.Column(
                "applicable",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column("outcome", sa.String(length=16), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )
        op.create_index("ix_llm_invocation_outcomes_scan_id", _TABLE, ["scan_id"])
        op.create_index("ix_llm_invocation_outcomes_finding_id", _TABLE, ["finding_id"])
        op.create_index("ix_llm_invocation_outcomes_tenant_id", _TABLE, ["tenant_id"])

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f'ALTER TABLE "{_TABLE}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{_TABLE}" FORCE ROW LEVEL SECURITY')
        op.execute(f'DROP POLICY IF EXISTS {_POLICY} ON "{_TABLE}"')
        op.execute(f"""
            CREATE POLICY {_POLICY} ON "{_TABLE}"
                USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
                WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
            """)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f'DROP POLICY IF EXISTS {_POLICY} ON "{_TABLE}"')
    if _has_table(_TABLE):
        op.drop_index("ix_llm_invocation_outcomes_tenant_id", table_name=_TABLE)
        op.drop_index("ix_llm_invocation_outcomes_finding_id", table_name=_TABLE)
        op.drop_index("ix_llm_invocation_outcomes_scan_id", table_name=_TABLE)
        op.drop_table(_TABLE)
