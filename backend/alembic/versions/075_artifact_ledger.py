"""075 — per-artifact accounting ledger (Wave 4, R-6.1.1 / R-6.1.2).

One row per artifact a scan produced, recording its accounting state (presented /
excluded / unprocessed) and, when excluded, a closed-enum reason. Tenant-scoped
with FORCE row-level security, consistent with the other tenant tables.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "075"
down_revision: str | None = "074"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "artifact_ledger"
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
            sa.Column(
                "scan_id",
                sa.String(length=36),
                sa.ForeignKey("scans.id", ondelete="CASCADE"),
                nullable=False,
            ),
            sa.Column(
                "report_id",
                sa.String(length=36),
                sa.ForeignKey("reports.id", ondelete="CASCADE"),
                nullable=True,
            ),
            sa.Column("evidence_id", sa.String(length=36), nullable=True),
            sa.Column("object_key", sa.String(length=512), nullable=True),
            sa.Column("kind", sa.String(length=32), nullable=True),
            sa.Column("size_bytes", sa.BigInteger(), nullable=True),
            sa.Column("source", sa.String(length=32), nullable=False),
            sa.Column("tool_run_id", sa.String(length=36), nullable=True),
            sa.Column("state", sa.String(length=32), nullable=False),
            sa.Column("exclusion_reason", sa.String(length=32), nullable=True),
            sa.Column("section_ref", sa.String(length=64), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )
        op.create_index("ix_artifact_ledger_scan_id", _TABLE, ["scan_id"])
        op.create_index("ix_artifact_ledger_report_id", _TABLE, ["report_id"])

    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f'ALTER TABLE "{_TABLE}" ENABLE ROW LEVEL SECURITY')
        op.execute(f'ALTER TABLE "{_TABLE}" FORCE ROW LEVEL SECURITY')
        op.execute(f'DROP POLICY IF EXISTS {_POLICY} ON "{_TABLE}"')
        op.execute(
            f"""
            CREATE POLICY {_POLICY} ON "{_TABLE}"
                USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
                WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
            """
        )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        op.execute(f'DROP POLICY IF EXISTS {_POLICY} ON "{_TABLE}"')
    if _has_table(_TABLE):
        op.drop_index("ix_artifact_ledger_report_id", table_name=_TABLE)
        op.drop_index("ix_artifact_ledger_scan_id", table_name=_TABLE)
        op.drop_table(_TABLE)
