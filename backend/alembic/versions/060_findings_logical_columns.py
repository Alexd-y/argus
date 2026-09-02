"""060 — add logical-finding columns to findings (schema-drift repair).

Revision ID: 060
Revises: 059
Create Date: 2026-09-02

The ``Finding`` ORM model (``src/db/models.py``) declares
``fingerprint_key``, ``verdict``, ``hypothesis`` and ``provenance`` but no
migration ever added them, so live databases raise
``UndefinedColumnError: column findings.fingerprint_key does not exist`` on
``GET /scans/{id}/findings``. All columns are nullable/additive so pre-existing
findings keep their semantics. Idempotent: only missing columns are added.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "060"
down_revision: str | None = "059"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _json_type() -> sa.types.TypeEngine:
    bind = op.get_bind()
    return postgresql.JSONB() if bind.dialect.name == "postgresql" else sa.JSON()


def _new_columns() -> tuple[tuple[str, sa.types.TypeEngine], ...]:
    json_type = _json_type()
    return (
        ("fingerprint_key", sa.String(64)),
        ("verdict", sa.String(32)),
        ("hypothesis", json_type),
        ("provenance", json_type),
    )


def _existing_columns() -> set[str]:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    return {col["name"] for col in inspector.get_columns("findings")}


def upgrade() -> None:
    existing = _existing_columns()
    for name, col_type in _new_columns():
        if name not in existing:
            op.add_column("findings", sa.Column(name, col_type, nullable=True))


def downgrade() -> None:
    existing = _existing_columns()
    for name, _col_type in reversed(_new_columns()):
        if name in existing:
            op.drop_column("findings", name)
