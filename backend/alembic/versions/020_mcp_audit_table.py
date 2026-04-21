"""ARG-045 — MCP per-call audit log + RLS.

Revision ID: 020
Revises: 019
Create Date: 2026-04-21

Context
-------
Cycle 4 ARG-039 finalised the MCP server (FastMCP runtime + 3 transports)
and ARG-035 wired the rate-limiter / webhooks but the per-call audit
trail was held in an in-memory ring buffer. ARG-045 promotes it to a
durable, tenant-scoped Postgres table so SOC operators can answer the
forensic question «which client invoked which tool, when, with what
result?» across restarts and rolling upgrades.

Schema
------
``mcp_audit`` columns:
  * audit_id        : VARCHAR(36)  — UUID PK
  * tenant_id       : VARCHAR(36)  — FK tenants(id) ON DELETE CASCADE
  * client_id_hash  : VARCHAR(64)  — SHA-256(client_id)[:64] — never raw
  * tool_name       : VARCHAR(120) — fully-qualified MCP tool name
  * status          : VARCHAR(24)  — ok | rate_limited | error | denied (CHECK)
  * duration_ms     : INTEGER      — server-side wall-clock (≥0)
  * created_at      : TIMESTAMPTZ  — server_default now()

Indexes:
  * ix_mcp_audit_tenant_created — list-by-tenant pagination + retention sweep.
  * ix_mcp_audit_tool_status    — operator dashboards (per-tool error rate).
  * ix_mcp_audit_client_hash    — per-client SLO + rate-limit forensics.

Security invariants
-------------------
* ``client_id_hash`` is the SHA-256 hex digest of the raw client_id,
  truncated to 64 chars. Raw client_id is NEVER persisted — Backlog
  §11 PII discipline + cardinality whitelist (matches the Prometheus
  label policy enforced by ARG-041).
* ``tenant_id`` MUST be passed by the caller; FK + RLS guarantee
  cross-tenant isolation.
* No request body / response body persisted — only metadata. Bodies
  remain in the existing structured-log pipeline (NDJSON, redacted).
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "020"
down_revision: str | None = "019"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

TABLE_NAME = "mcp_audit"

ALLOWED_STATUSES = ("ok", "rate_limited", "error", "denied", "timeout")


def upgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    op.create_table(
        TABLE_NAME,
        sa.Column("audit_id", sa.String(36), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.String(36),
            sa.ForeignKey("tenants.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("client_id_hash", sa.String(64), nullable=False),
        sa.Column("tool_name", sa.String(120), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            f"status IN ({', '.join(repr(s) for s in ALLOWED_STATUSES)})",
            name="ck_mcp_audit_status",
        ),
        sa.CheckConstraint("duration_ms >= 0", name="ck_mcp_audit_duration_nonneg"),
        sa.CheckConstraint(
            "char_length(client_id_hash) = 64", name="ck_mcp_audit_client_hash_len"
        ),
    )

    op.create_index(
        "ix_mcp_audit_tenant_created", TABLE_NAME, ["tenant_id", "created_at"]
    )
    op.create_index(
        "ix_mcp_audit_tool_status", TABLE_NAME, ["tool_name", "status"]
    )
    op.create_index(
        "ix_mcp_audit_client_hash", TABLE_NAME, ["client_id_hash"]
    )

    if is_postgres:
        op.execute("ALTER TABLE mcp_audit ENABLE ROW LEVEL SECURITY")
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON mcp_audit")
        op.execute(
            """
            CREATE POLICY tenant_isolation ON mcp_audit
                USING (tenant_id = current_setting('app.current_tenant_id', true)::text)
                WITH CHECK (tenant_id = current_setting('app.current_tenant_id', true)::text)
            """
        )


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        op.execute("DROP POLICY IF EXISTS tenant_isolation ON mcp_audit")
        op.execute("ALTER TABLE mcp_audit DISABLE ROW LEVEL SECURITY")

    op.drop_index("ix_mcp_audit_client_hash", table_name=TABLE_NAME)
    op.drop_index("ix_mcp_audit_tool_status", table_name=TABLE_NAME)
    op.drop_index("ix_mcp_audit_tenant_created", table_name=TABLE_NAME)
    op.drop_table(TABLE_NAME)
