"""080 — dark_web_observations: passive Dark Web Monitoring (DWM) observations.

Tenant-scoped with FORCE row-level security, consistent with the other tenant
tables. ``scan_id`` is an FK to ``scans`` (CASCADE); ``finding_id`` is an FK to
``findings`` (SET NULL) set by the per-finding correlation pass (T2). Each row
carries a reproducible provenance (source_ref + timestamps + raw_sha256 +
raw_object_key + chain_hash). ``evidence_tier`` is capped at 2 at the app layer.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "080"
down_revision: str | None = "079"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "dark_web_observations"
_POLICY = "tenant_isolation"

_JSON = postgresql.JSONB().with_variant(sa.JSON(), "sqlite")


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
                "finding_id",
                sa.String(length=36),
                sa.ForeignKey("findings.id", ondelete="SET NULL"),
                nullable=True,
            ),
            sa.Column("selector_kind", sa.String(length=20), nullable=False),
            sa.Column("selector_value_hash", sa.String(length=64), nullable=False),
            sa.Column("source_network", sa.String(length=20), nullable=False),
            sa.Column("source_ref", sa.Text(), nullable=True),
            sa.Column("exposure_type", sa.String(length=30), nullable=False),
            sa.Column("severity", sa.String(length=20), nullable=False, server_default=sa.text("'info'")),
            sa.Column(
                "confidence",
                sa.String(length=20),
                nullable=False,
                server_default=sa.text("'advisory'"),
            ),
            sa.Column(
                "evidence_tier",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("1"),
                comment="1=INFORMATIONAL, 2=SUSPECTED (DWM hard cap = 2, never 3/4)",
            ),
            sa.Column("observed_at", sa.DateTime(timezone=True), nullable=True),
            sa.Column(
                "collected_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.text("now()"),
            ),
            sa.Column("raw_object_key", sa.String(length=512), nullable=True),
            sa.Column("raw_sha256", sa.String(length=64), nullable=True),
            sa.Column("chain_hash", sa.String(length=64), nullable=True),
            sa.Column("redacted_summary", sa.Text(), nullable=True),
            sa.Column("provenance", _JSON, nullable=True),
            sa.Column("collector", sa.String(length=60), nullable=True),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                server_default=sa.text("now()"),
                nullable=False,
            ),
        )
        op.create_index("ix_dark_web_observations_tenant_scan", _TABLE, ["tenant_id", "scan_id"])
        op.create_index("ix_dark_web_observations_finding_id", _TABLE, ["finding_id"])
        op.create_index("ix_dark_web_observations_source_network", _TABLE, ["source_network"])
        op.create_index("ix_dark_web_observations_exposure_type", _TABLE, ["exposure_type"])

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
        op.drop_index("ix_dark_web_observations_exposure_type", table_name=_TABLE)
        op.drop_index("ix_dark_web_observations_source_network", table_name=_TABLE)
        op.drop_index("ix_dark_web_observations_finding_id", table_name=_TABLE)
        op.drop_index("ix_dark_web_observations_tenant_scan", table_name=_TABLE)
        op.drop_table(_TABLE)
