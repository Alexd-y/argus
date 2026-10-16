"""076 — object-storage keys for redacted LLM prompt/response text (Wave 5, R-9.1/R-9.3).

Adds two nullable columns to ``gateway_invocations`` so the telemetry row can
reference the REDACTED prompt/response text stored in object storage (the text
itself never lives in a DB column). NULL when text capture
(``settings.llm_telemetry_store_text``) is off, which is the default.

Additive and idempotent; no RLS change (the table's policy, if any, is untouched).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "076"
down_revision: str | None = "075"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE = "gateway_invocations"
_COLUMNS = ("prompt_object_key", "response_object_key")


def _has_table(name: str) -> bool:
    return name in sa.inspect(op.get_bind()).get_table_names()


def _existing_columns() -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(_TABLE)}


def upgrade() -> None:
    if not _has_table(_TABLE):
        return
    existing = _existing_columns()
    for col in _COLUMNS:
        if col not in existing:
            op.add_column(_TABLE, sa.Column(col, sa.String(length=1024), nullable=True))


def downgrade() -> None:
    if not _has_table(_TABLE):
        return
    existing = _existing_columns()
    for col in _COLUMNS:
        if col in existing:
            op.drop_column(_TABLE, col)
