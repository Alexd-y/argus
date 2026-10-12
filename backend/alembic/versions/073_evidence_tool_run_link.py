"""073 — evidence belongs to a tool run before a finding (wave 2, R-5.3.1).

Raw tool-run evidence is produced before any finding is parsed, so:

* ``evidence.finding_id`` becomes nullable (NULL = not yet linked to a finding);
* ``evidence.tool_run_id`` (added nullable in 072) gains a foreign key to
  ``tool_runs.id`` (``ON DELETE SET NULL``) and a lookup index.

Idempotent guards mirror 071/072. Postgres-only DDL (ALTER COLUMN nullability +
ADD CONSTRAINT); the offline SQLite round-trip is covered by 072, this one is
exercised against real Postgres.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "073"
down_revision: str | None = "072"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "evidence"
_FK = "fk_evidence_tool_run_id"
_INDEX = "ix_evidence_tool_run_id"


def _inspector() -> sa.engine.reflection.Inspector:
    return sa.inspect(op.get_bind())


def _has_fk(name: str) -> bool:
    return any(fk["name"] == name for fk in _inspector().get_foreign_keys(_TABLE))


def _has_index(name: str) -> bool:
    return any(ix["name"] == name for ix in _inspector().get_indexes(_TABLE))


def upgrade() -> None:
    op.alter_column(_TABLE, "finding_id", existing_type=sa.String(length=36), nullable=True)
    if not _has_fk(_FK):
        op.create_foreign_key(
            _FK, _TABLE, "tool_runs", ["tool_run_id"], ["id"], ondelete="SET NULL"
        )
    if not _has_index(_INDEX):
        op.create_index(_INDEX, _TABLE, ["tool_run_id"])


def downgrade() -> None:
    if _has_index(_INDEX):
        op.drop_index(_INDEX, table_name=_TABLE)
    if _has_fk(_FK):
        op.drop_constraint(_FK, _TABLE, type_="foreignkey")
    # Revert to NOT NULL only when no NULL finding_id rows exist (best-effort).
    bind = op.get_bind()
    null_rows = bind.execute(
        sa.text(f"SELECT COUNT(*) FROM {_TABLE} WHERE finding_id IS NULL")  # noqa: S608
    ).scalar()
    if not null_rows:
        op.alter_column(_TABLE, "finding_id", existing_type=sa.String(length=36), nullable=False)
