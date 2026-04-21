"""ARG-045 — MCP webhook / notification dispatch log + RLS.

Revision ID: 021
Revises: 020
Create Date: 2026-04-21

Context
-------
Cycle 4 ARG-035 wired the MCP webhook fan-out (Slack / Linear / Jira)
behind a Redis-backed delivery worker but kept the per-attempt history
in Redis hashes only (TTL 24h). ARG-045 hardens this into a durable
``notification_dispatch_log`` so the operator UI can display retry
chains, last-error classes and at-least-once delivery proofs.

Schema
------
``notification_dispatch_log`` columns:
  * dispatch_id      : VARCHAR(36)  — UUID PK
  * tenant_id        : VARCHAR(36)  — FK tenants(id) ON DELETE CASCADE
  * event_type       : VARCHAR(80)  — fully-qualified event name
  * provider         : VARCHAR(24)  — slack | linear | jira (CHECK)
  * status           : VARCHAR(24)  — queued | delivered | failed | dlq (CHECK)
  * attempt_count    : INTEGER      — 0..MAX_RETRIES (default 5)
  * last_error_class : VARCHAR(120) — exception class name only — never message
  * idempotency_key  : VARCHAR(120) — UNIQUE — caller-provided dedup token
  * dispatched_at    : TIMESTAMPTZ  — last delivery attempt timestamp
  * created_at       : TIMESTAMPTZ  — server_default now()

Indexes:
  * ix_notification_dispatch_log_idem    — UNIQUE (idempotency_key) — global,
                                            spans tenants. Caller MUST namespace
                                            the key with their tenant prefix.
  * ix_notification_dispatch_log_tenant  — list-by-tenant + status.
  * ix_notification_dispatch_log_provider — operator dashboard per-provider.

Security invariants
-------------------
* ``last_error_class`` records ONLY the exception class name (e.g.
  ``slack_sdk.errors.SlackApiError``). Free-form messages, response
  bodies and stack traces are NEVER persisted — they may carry tokens
  or PII. Bodies remain in NDJSON logs only, redacted by ``structlog``.
* RLS ``tenant_isolation`` mirrors the rest of the schema.
* ``idempotency_key`` UNIQUE is global on purpose: it lets a CI runner
  replay the same delivery N times safely (insert returns conflict →
  reuse existing record). Callers MUST embed ``tenant_id`` in the key
  to keep collisions avoidable across tenants — see
  ``backend/src/mcp/runtime/notifications.py::build_idempotency_key()``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "021"
down_revision: str | None = "020"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE_NAME = "notification_dispatch_log"

ALLOWED_PROVIDERS = ("slack", "linear", "jira")
ALLOWED_STATUSES = ("queued", "delivered", "failed", "dlq", "retry")


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    op.create_table(
        TABLE_NAME,
        sa.Column("dispatch_id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("provider", sa.String(24), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column(
            "attempt_count", sa.Integer(), nullable=False, server_default="0"
        ),
        sa.Column("last_error_class", sa.String(120), nullable=True),
        sa.Column("idempotency_key", sa.String(120), nullable=False),
        sa.Column(
            "dispatched_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            f"provider IN ({', '.join(repr(p) for p in ALLOWED_PROVIDERS)})",
            name="ck_notif_dispatch_provider",
        ),
        sa.CheckConstraint(
            f"status IN ({', '.join(repr(s) for s in ALLOWED_STATUSES)})",
            name="ck_notif_dispatch_status",
        ),
        sa.CheckConstraint("attempt_count >= 0", name="ck_notif_dispatch_attempts_nonneg"),
        sa.UniqueConstraint("idempotency_key", name="uq_notif_dispatch_idem"),
    )

    op.create_index(
        "ix_notification_dispatch_log_tenant",
        TABLE_NAME,
        ["tenant_id", "status", "created_at"],
    )
    op.create_index(
        "ix_notification_dispatch_log_provider",
        TABLE_NAME,
        ["provider", "status"],
    )

    if is_postgres:
        op.execute(
            "ALTER TABLE notification_dispatch_log ENABLE ROW LEVEL SECURITY"
        )
        op.execute(
            "DROP POLICY IF EXISTS tenant_isolation ON notification_dispatch_log"
        )
        op.execute(
            """
            CREATE POLICY tenant_isolation ON notification_dispatch_log
                USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
                WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
            """
        )


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        op.execute(
            "DROP POLICY IF EXISTS tenant_isolation ON notification_dispatch_log"
        )
        op.execute(
            "ALTER TABLE notification_dispatch_log DISABLE ROW LEVEL SECURITY"
        )

    op.drop_index("ix_notification_dispatch_log_provider", table_name=TABLE_NAME)
    op.drop_index("ix_notification_dispatch_log_tenant", table_name=TABLE_NAME)
    op.drop_table(TABLE_NAME)
