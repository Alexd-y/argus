"""059 — Canonical scan_profile + Profile Resolver columns on scans.

Revision ID: 059
Revises: 058
Create Date: 2026-08-23

Adds the canonical external ``scan_profile`` (quick|light|deep) plus the
resolved internal knobs persisted for analytics and idempotent resume. All
columns are nullable/additive so pre-existing scans keep their semantics
(Requirements P6 — legacy ``scan_mode=deep`` stays production-deep).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "059"
down_revision: str | None = "058"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


_NEW_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("scan_profile", sa.String(16)),
    ("resolved_scan_mode", sa.String(20)),
    ("nuclei_profile", sa.String(64)),
    ("engagement_id", sa.String(36)),
    ("lab_lease_id", sa.String(36)),
    ("profile_version", sa.String(16)),
    ("report_snapshot_version", sa.String(16)),
)


def _existing_columns() -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {col["name"] for col in inspector.get_columns("scans")}


def upgrade() -> None:
    existing = _existing_columns()
    for name, col_type in _NEW_COLUMNS:
        if name not in existing:
            op.add_column("scans", sa.Column(name, col_type, nullable=True))
    op.create_index(
        "ix_scans_tenant_scan_profile",
        "scans",
        ["tenant_id", "scan_profile"],
    )


def downgrade() -> None:
    op.drop_index("ix_scans_tenant_scan_profile", table_name="scans")
    existing = _existing_columns()
    for name, _col_type in reversed(_NEW_COLUMNS):
        if name in existing:
            op.drop_column("scans", name)
