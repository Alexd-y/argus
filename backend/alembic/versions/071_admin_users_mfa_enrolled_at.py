"""071 — add admin_users.mfa_enrolled_at.

C7-T03 follow-up: persist the enrolment timestamp set when confirm_enrollment first
enables MFA, so ``GET /auth/admin/mfa/status`` can report ``enrolled_at`` instead of
a hardcoded ``None``. Nullable, additive, backward compatible — existing rows stay
NULL until the admin (re-)enrols.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "071"
down_revision: str | None = "070"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "admin_users"
_COLUMN = "mfa_enrolled_at"


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    return any(col["name"] == column for col in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    if not _has_column(_TABLE, _COLUMN):
        op.add_column(_TABLE, sa.Column(_COLUMN, sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    if _has_column(_TABLE, _COLUMN):
        op.drop_column(_TABLE, _COLUMN)
