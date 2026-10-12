"""072 — evidence contract fields (R-7.1).

Wave 1 widens the ``evidence`` table with the fields the evidence contract needs
in waves 2–3, so a second migration is not required later: evidence kind,
checksum algorithm + value, size, producing tool run / name / version, start and
finish timestamps, a negative-control flag with a pointer to the paired positive
evidence, a repeatability attempt number, a redaction-applied flag, and the
artifact-ledger accounting state.

All columns are nullable and additive, so existing rows stay valid. The
``evidence`` table already carries ``tenant_id`` and has row-level security
enabled (migration 002); adding nullable columns inherits that policy, so no new
RLS wiring is introduced here. Idempotent add/drop guards mirror migration 071.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "072"
down_revision: str | None = "071"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "evidence"

#: (column name, column type) — all nullable, all additive.
_COLUMNS: tuple[tuple[str, sa.types.TypeEngine], ...] = (
    ("kind", sa.String(32)),
    ("checksum_algorithm", sa.String(20)),
    ("checksum_value", sa.String(128)),
    ("size_bytes", sa.BigInteger()),
    ("tool_run_id", sa.String(36)),
    ("tool_name", sa.String(128)),
    ("tool_version", sa.String(64)),
    ("started_at", sa.DateTime(timezone=True)),
    ("finished_at", sa.DateTime(timezone=True)),
    ("is_negative_control", sa.Boolean()),
    ("paired_evidence_id", sa.String(36)),
    ("repro_attempt", sa.Integer()),
    ("redaction_applied", sa.Boolean()),
    ("ledger_state", sa.String(32)),
)


def _has_column(table: str, column: str) -> bool:
    bind = op.get_bind()
    return any(col["name"] == column for col in sa.inspect(bind).get_columns(table))


def upgrade() -> None:
    for name, type_ in _COLUMNS:
        if not _has_column(_TABLE, name):
            op.add_column(_TABLE, sa.Column(name, type_, nullable=True))


def downgrade() -> None:
    for name, _type in reversed(_COLUMNS):
        if _has_column(_TABLE, name):
            op.drop_column(_TABLE, name)
