"""ARG-045 (with ARG-044) — EPSS scores + CISA KEV catalogue.

Revision ID: 023
Revises: 022
Create Date: 2026-04-21

Context
-------
ARG-044 (EPSS / KEV enrichment loops) shipped the SQLAlchemy ORM models
(``EpssScore``, ``KevEntry``) plus the async repositories. The DDL
migration was deliberately deferred to ARG-045 so the schema lands
together with the rest of the Cycle 5 finalisation set.

Schema
------
``epss_scores`` (NOT tenant-scoped — global threat intel):
  * cve_id          : VARCHAR(20)   PK — CVE-YYYY-NNNNN (uppercase)
  * epss_score      : DOUBLE PRECISION — 0..1 probability over 30 days
  * epss_percentile : DOUBLE PRECISION — 0..1 model percentile
  * model_date      : DATE          — FIRST.org model snapshot
  * created_at      : TIMESTAMPTZ   — server_default now()
  * updated_at      : TIMESTAMPTZ   — server_default now() ON UPDATE now()

  Indexes:
  * ix_epss_scores_model_date — staleness sweep ("rows older than N days").

``kev_catalog`` (NOT tenant-scoped — global threat intel):
  * cve_id               : VARCHAR(20)  PK
  * vendor_project       : VARCHAR(255) NOT NULL DEFAULT ''
  * product              : VARCHAR(255) NOT NULL DEFAULT ''
  * vulnerability_name   : VARCHAR(500) NOT NULL DEFAULT ''
  * date_added           : DATE         NOT NULL
  * short_description    : TEXT         NOT NULL DEFAULT ''
  * required_action      : TEXT         NOT NULL DEFAULT ''
  * due_date             : DATE         NULL
  * known_ransomware_use : BOOLEAN      NOT NULL DEFAULT FALSE
  * notes                : TEXT         NULL
  * created_at           : TIMESTAMPTZ  server_default now()
  * updated_at           : TIMESTAMPTZ  server_default now() ON UPDATE now()

  Indexes:
  * ix_kev_catalog_date_added — "added in the last 30 days" dashboard.

Why no RLS
----------
EPSS and KEV are public CVE intel. Any tenant may need to enrich any
CVE — there is no per-tenant variation in the upstream feed. Adding RLS
would create a chicken-and-egg in the Celery beat refresh worker (no
tenant context for the writer) and forces N copies of identical data
across tenants. Both tables are READ-ONLY for the request path; only
the daily refresh job has DML rights via a dedicated service role.

Backwards compatibility
-----------------------
* New tables only.
* No changes to existing tables.
* downgrade() drops both tables in reverse order.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "023"
down_revision: str | None = "022"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

EPSS_TABLE = "epss_scores"
KEV_TABLE = "kev_catalog"


def upgrade() -> None:
    op.create_table(
        EPSS_TABLE,
        sa.Column("cve_id", sa.String(20), primary_key=True),
        sa.Column("epss_score", sa.Float(), nullable=False),
        sa.Column("epss_percentile", sa.Float(), nullable=False),
        sa.Column("model_date", sa.Date(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "epss_score >= 0 AND epss_score <= 1",
            name="ck_epss_score_range",
        ),
        sa.CheckConstraint(
            "epss_percentile >= 0 AND epss_percentile <= 1",
            name="ck_epss_percentile_range",
        ),
    )
    op.create_index("ix_epss_scores_model_date", EPSS_TABLE, ["model_date"])

    op.create_table(
        KEV_TABLE,
        sa.Column("cve_id", sa.String(20), primary_key=True),
        sa.Column(
            "vendor_project",
            sa.String(255),
            nullable=False,
            server_default="",
        ),
        sa.Column("product", sa.String(255), nullable=False, server_default=""),
        sa.Column(
            "vulnerability_name",
            sa.String(500),
            nullable=False,
            server_default="",
        ),
        sa.Column("date_added", sa.Date(), nullable=False),
        sa.Column(
            "short_description", sa.Text(), nullable=False, server_default=""
        ),
        sa.Column(
            "required_action", sa.Text(), nullable=False, server_default=""
        ),
        sa.Column("due_date", sa.Date(), nullable=True),
        sa.Column(
            "known_ransomware_use",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_kev_catalog_date_added", KEV_TABLE, ["date_added"])


def downgrade() -> None:
    op.drop_index("ix_kev_catalog_date_added", table_name=KEV_TABLE)
    op.drop_table(KEV_TABLE)
    op.drop_index("ix_epss_scores_model_date", table_name=EPSS_TABLE)
    op.drop_table(EPSS_TABLE)
