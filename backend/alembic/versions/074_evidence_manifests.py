"""074 — evidence-base manifest table (wave 2, R-7.3 / R-5.6.2).

Per-scan manifest: root hash over the sorted evidence checksums, artifact count,
total size, and a link to the audit event recording formation. Tenant-scoped
with FORCE row-level security, consistent with the other tenant tables.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "074"
down_revision: str | None = "073"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "evidence_manifests"
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
            sa.Column("root_hash", sa.String(length=64), nullable=False),
            sa.Column("artifact_count", sa.Integer(), nullable=False, server_default="0"),
            sa.Column("total_size_bytes", sa.BigInteger(), nullable=True),
            sa.Column("audit_event_id", sa.String(length=36), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )
        op.create_index("ix_evidence_manifests_scan_id", _TABLE, ["scan_id"])

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
        op.drop_index("ix_evidence_manifests_scan_id", table_name=_TABLE)
        op.drop_table(_TABLE)
