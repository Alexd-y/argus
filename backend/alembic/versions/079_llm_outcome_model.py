"""079 — model dimension on llm_invocation_outcomes (Wave 5, R-9.11).

Adds a nullable ``model`` column so arbiter-outcome rows can be aggregated per
(task, model) — the "task → model" quality pairing. Additive and idempotent.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "079"
down_revision: str | None = "078"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "llm_invocation_outcomes"
_COLUMN = "model"


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _existing_columns() -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(_TABLE)}


def upgrade() -> None:
    if not _has_table(_TABLE):
        return
    if _COLUMN not in _existing_columns():
        op.add_column(_TABLE, sa.Column(_COLUMN, sa.String(length=128), nullable=True))


def downgrade() -> None:
    if not _has_table(_TABLE):
        return
    if _COLUMN in _existing_columns():
        op.drop_column(_TABLE, _COLUMN)
