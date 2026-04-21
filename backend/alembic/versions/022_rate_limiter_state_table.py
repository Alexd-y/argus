"""ARG-045 — Distributed token-bucket rate-limiter state.

Revision ID: 022
Revises: 021
Create Date: 2026-04-21

Context
-------
Cycle 4 ARG-035 introduced the MCP rate-limiter as a Redis-only token
bucket. ARG-045 adds a Postgres-backed persistence layer for the
recovery path: on Redis cold-start (eviction, container restart) the
limiter rehydrates the per-key bucket state from this table so a
malicious caller cannot reset their bucket by causing a Redis flap.

Schema
------
``rate_limiter_state`` columns:
  * key                 : VARCHAR(220) — composite ``<scope>:<tenant_id>:<client_id_hash>``
                                          (PK; opaque to Postgres)
  * tokens_available    : DOUBLE PRECISION — fractional tokens remaining
  * last_refill_at      : TIMESTAMPTZ — last time the limiter refilled
  * bucket_capacity     : INTEGER     — max tokens (≥1)
  * refill_rate_per_sec : DOUBLE PRECISION — tokens added per wall-clock second
  * updated_at          : TIMESTAMPTZ — server_default now() ON UPDATE now()

Why no RLS
----------
The rate-limiter is **infrastructure** (the kill-switch surface for the
whole platform). It is read/written by the limiter daemon under a
service identity and the operator UI under a privileged role. The
``tenant_id`` is captured INSIDE ``key`` (the ``<scope>:<tenant>:<hash>``
composite) so per-tenant filtering happens at the application layer
through key-prefix scans. RLS would create a chicken-and-egg with the
recovery path (limiter MUST be able to read state before the request
context establishes ``app.current_tenant_id``).

Backward compatibility
----------------------
* Brand-new table — no impact on existing tables.
* ``app/limiters/registry.py`` reads/writes through SQLAlchemy session
  with explicit ``SELECT FOR UPDATE`` to avoid lost-update under
  concurrent refill.
* Downgrade drops the table — runtime falls back to Redis-only mode
  (degraded but still functional).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "022"
down_revision: str | None = "021"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE_NAME = "rate_limiter_state"


def upgrade() -> None:
    op.create_table(
        TABLE_NAME,
        sa.Column("key", sa.String(220), primary_key=True),
        sa.Column(
            "tokens_available",
            sa.Float(),
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "last_refill_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("bucket_capacity", sa.Integer(), nullable=False),
        sa.Column(
            "refill_rate_per_sec",
            sa.Float(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "tokens_available >= 0",
            name="ck_rl_state_tokens_nonneg",
        ),
        sa.CheckConstraint(
            "bucket_capacity >= 1",
            name="ck_rl_state_capacity_min",
        ),
        sa.CheckConstraint(
            "refill_rate_per_sec >= 0",
            name="ck_rl_state_refill_nonneg",
        ),
        sa.CheckConstraint(
            "tokens_available <= bucket_capacity",
            name="ck_rl_state_tokens_le_capacity",
        ),
    )

    # Optional secondary index for prefix scans during operator audits;
    # most lookups are PK hits so we keep this surface minimal.
    op.create_index(
        "ix_rate_limiter_state_updated", TABLE_NAME, ["updated_at"]
    )


def downgrade() -> None:
    op.drop_index("ix_rate_limiter_state_updated", table_name=TABLE_NAME)
    op.drop_table(TABLE_NAME)
