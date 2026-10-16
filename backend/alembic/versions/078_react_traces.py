"""078 — react_traces: full multi-step ReAct reasoning trace (Wave 5, R-9.4).

Scalar metadata inline; the full ordered steps live in object storage, referenced
by ``steps_object_key``. Tenant-scoped with FORCE row-level security, consistent
with the other tenant tables. scan_id is a soft reference (no FK).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "078"
down_revision: str | None = "077"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "react_traces"
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
            sa.Column("answer_hash", sa.String(length=64), nullable=True),
            sa.Column("iterations", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("steps_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
            sa.Column("confidence", sa.Float(), nullable=False, server_default=sa.text("0.0")),
            sa.Column(
                "total_duration_seconds",
                sa.Float(),
                nullable=False,
                server_default=sa.text("0.0"),
            ),
            sa.Column("stop_reason", sa.String(length=32), nullable=True),
            sa.Column(
                "evidence_backed",
                sa.Boolean(),
                nullable=False,
                server_default=sa.text("false"),
            ),
            sa.Column("error", sa.String(length=256), nullable=True),
            sa.Column("steps_object_key", sa.String(length=1024), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )
        op.create_index("ix_react_traces_scan_id", _TABLE, ["scan_id"])
        op.create_index("ix_react_traces_tenant_id", _TABLE, ["tenant_id"])

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
        op.drop_index("ix_react_traces_tenant_id", table_name=_TABLE)
        op.drop_index("ix_react_traces_scan_id", table_name=_TABLE)
        op.drop_table(_TABLE)
