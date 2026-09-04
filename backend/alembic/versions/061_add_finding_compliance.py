"""061 — add compliance column to findings (ISO 27001 / SOC 2 mapping).

Revision ID: 061
Revises: 060
Create Date: 2026-09-05

Block 4.2: each finding is annotated with the ISO 27001 (Annex A) and SOC 2
(Trust Services Criteria) controls it maps to, stored as a JSONB list of
``{framework, control_id, control_name}``. Additive and nullable, so existing
findings keep their semantics. Idempotent: only added when missing.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "061"
down_revision: str | None = "060"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.types.TypeEngine:
    bind = op.get_bind()
    return postgresql.JSONB() if bind.dialect.name == "postgresql" else sa.JSON()


def _existing_columns() -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {col["name"] for col in inspector.get_columns("findings")}


def upgrade() -> None:
    if "compliance" not in _existing_columns():
        op.add_column("findings", sa.Column("compliance", _json_type(), nullable=True))


def downgrade() -> None:
    if "compliance" in _existing_columns():
        op.drop_column("findings", "compliance")
