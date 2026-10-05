"""069 — add scans.error_message.

Stores a human-readable reason a scan ended in ``status="failed"`` (timeout,
phase error, lab lease required) so ``GET /scans/:id`` can surface *why* a scan
failed instead of the generic "An unexpected error occurred" fallback.
Nullable, backward compatible — healthy scans leave it null.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "069"
down_revision: str | None = "068"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "scans"
_COLUMN = "error_message"


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    return any(col["name"] == column for col in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    if not _has_column(_TABLE, _COLUMN):
        op.add_column(_TABLE, sa.Column(_COLUMN, sa.Text(), nullable=True))


def downgrade() -> None:
    if _has_column(_TABLE, _COLUMN):
        op.drop_column(_TABLE, _COLUMN)
