"""042 — Findings: evidence_tier, payload_attempted, payload_successful, taint_path, code_location

Revision ID: 042
Revises: 041
Create Date: 2026-05-26

Adds exploitation-evidence columns to findings table.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "042"
down_revision: str | None = "041"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

FINDINGS = "findings"


def upgrade() -> None:
    op.execute(
        f"ALTER TABLE {FINDINGS} ADD COLUMN IF NOT EXISTS evidence_tier INTEGER"
    )
    op.execute(
        f"COMMENT ON COLUMN {FINDINGS}.evidence_tier "
        "IS '1=INFORMATIONAL, 2=SUSPECTED, 3=CONFIRMED, 4=EXPLOITED'"
    )
    op.execute(
        f"ALTER TABLE {FINDINGS} ADD COLUMN IF NOT EXISTS payload_attempted JSONB"
    )
    op.execute(
        f"ALTER TABLE {FINDINGS} ADD COLUMN IF NOT EXISTS payload_successful JSONB"
    )
    op.execute(
        f"ALTER TABLE {FINDINGS} ADD COLUMN IF NOT EXISTS taint_path JSONB"
    )
    op.execute(
        f"ALTER TABLE {FINDINGS} ADD COLUMN IF NOT EXISTS code_location VARCHAR(500)"
    )


def downgrade() -> None:
    op.execute(f"ALTER TABLE {FINDINGS} DROP COLUMN IF EXISTS code_location")
    op.execute(f"ALTER TABLE {FINDINGS} DROP COLUMN IF EXISTS taint_path")
    op.execute(f"ALTER TABLE {FINDINGS} DROP COLUMN IF EXISTS payload_successful")
    op.execute(f"ALTER TABLE {FINDINGS} DROP COLUMN IF EXISTS payload_attempted")
    op.execute(f"ALTER TABLE {FINDINGS} DROP COLUMN IF EXISTS evidence_tier")