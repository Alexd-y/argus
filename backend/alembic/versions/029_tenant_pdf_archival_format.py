"""tenants.pdf_archival_format — per-tenant PDF archival format flag.

Revision ID: 029
Revises: 028
Create Date: 2026-04-22

ARG-058 / Cycle 6 Batch 6 / B6-T02 / T48.

Per-tenant control over PDF archival format. Default ``'standard'`` preserves
backward-compat — existing tenants continue rendering with the WeasyPrint /
legacy LaTeX path. Operators flip to ``'pdfa-2u'`` once their compliance audit
requires it; the LatexBackend then injects the PDF/A-2u preamble + ICC profile
shipped in B6-T01 (see ``backend/templates/reports/_latex/_preamble/pdfa.tex.j2``).

Schema choice — flat VARCHAR(16) + CHECK constraint
---------------------------------------------------
The user-spec for B6-T02 (D-4 in the batch plan) explicitly mandates a flat
``VARCHAR(16) NOT NULL DEFAULT 'standard'`` column with a portable
``CHECK`` constraint enforcing the closed taxonomy ``('standard', 'pdfa-2u')``.

Two reasons we did NOT use a Postgres ENUM type:

1. The ``Tenant`` ORM uses a flat-column convention for tenant-config (see
   ``rate_limit_rpm``, ``scope_blacklist``, ``retention_days``,
   ``exports_sarif_junit_enabled``). A new ENUM type splits the admin API
   schema between flat fields and one ENUM-backed field — needless friction
   for a 2-value taxonomy.
2. ``CHECK (col IN (...))`` round-trips byte-stable across Postgres and
   SQLite, which keeps the dialect-free ``test_alembic_smoke.py`` chain
   green without dialect branching in this revision.

Backfill
--------
The ``server_default='standard'`` populates every existing row at the moment
the column is added (Postgres ALTER TABLE ... ADD COLUMN with a non-volatile
DEFAULT is in-place). The explicit ``UPDATE`` below is therefore *defensive*
— it makes the migration safe to re-run on an environment that pre-creates
the column without the default (e.g. a hand-written hotfix that left rows
NULL before declaring the column NOT NULL).

Backwards compatibility
-----------------------
* Brand-new column on an existing table — no impact on existing rows or
  queries.
* ``downgrade()`` is fully idempotent: drops the CHECK constraint with
  ``IF EXISTS`` (Postgres) before dropping the column.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

import sqlalchemy as sa
from alembic import op

revision: str = "029"
down_revision: str | None = "028"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE_NAME: Final[str] = "tenants"
COLUMN_NAME: Final[str] = "pdf_archival_format"
CHECK_NAME: Final[str] = "ck_tenants_pdf_archival_format"
ALLOWED_VALUES: Final[tuple[str, ...]] = ("standard", "pdfa-2u")
DEFAULT_VALUE: Final[str] = "standard"


def upgrade() -> None:
    """Add ``pdf_archival_format`` VARCHAR(16) NOT NULL DEFAULT 'standard'."""
    op.add_column(
        TABLE_NAME,
        sa.Column(
            COLUMN_NAME,
            sa.String(16),
            nullable=False,
            server_default=DEFAULT_VALUE,
        ),
    )

    op.execute(
        sa.text(
            f"UPDATE {TABLE_NAME} "
            f"SET {COLUMN_NAME} = :default_value "
            f"WHERE {COLUMN_NAME} IS NULL"
        ).bindparams(default_value=DEFAULT_VALUE)
    )

    allowed_sql = ", ".join(f"'{value}'" for value in ALLOWED_VALUES)
    op.create_check_constraint(
        CHECK_NAME,
        TABLE_NAME,
        f"{COLUMN_NAME} IN ({allowed_sql})",
    )


def downgrade() -> None:
    """Drop CHECK constraint + column. Idempotent on Postgres."""
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        op.execute(
            f'ALTER TABLE "{TABLE_NAME}" DROP CONSTRAINT IF EXISTS {CHECK_NAME}'
        )
    else:
        with op.batch_alter_table(TABLE_NAME) as batch_op:
            batch_op.drop_constraint(CHECK_NAME, type_="check")

    op.drop_column(TABLE_NAME, COLUMN_NAME)
