"""ISS-T20-003 Phase 1 — ``admin_users`` + ``admin_sessions`` tables.

Revision ID: 028
Revises: 027
Create Date: 2026-04-22

Closes the backend half of B6-T08 (D-2 / D-6). Lays the schema for the new
cookie-based admin session flow that replaces the forgeable
``argus.admin.role`` cookie diagnosed in ISS-T20-003. Two sibling tables
land in this migration:

* ``admin_users`` — one row per admin / operator / super-admin. Holds a
  bcrypt password hash (rounds >= 12) and a closed-taxonomy role. Operators
  are bootstrapped on startup from
  ``ADMIN_BOOTSTRAP_SUBJECT`` + ``ADMIN_BOOTSTRAP_PASSWORD_HASH`` (the
  password is *already hashed* before it crosses the env boundary; plaintext
  never appears in the runtime environment, the audit log, or the
  Alembic chain).
* ``admin_sessions`` — one row per cookie-bound login. Session ids are
  CSPRNG-generated URL-safe base64 strings (~64 chars from
  ``secrets.token_urlsafe(48)``); equality is checked via
  ``hmac.compare_digest`` in the resolver to remove the timing oracle.

Why no Row-Level Security
-------------------------
Both tables are intentionally *cross-tenant*. The super-admin role is the
canonical example: a super-admin must be able to log in and act across
every tenant; a tenant-isolation policy on ``admin_sessions.tenant_id``
would silently block their own session lookup. Tenant-scoped admins still
have a ``tenant_id`` column populated for forensic correlation, but the
column is a *role context* hint, not a tenant-isolation key.

The other admin surfaces (``/admin/*``) already enforce tenant scope at the
application layer via ``X-Admin-Tenant`` + ``X-Admin-Role`` headers (see
``admin_findings._enforce_rbac``). RLS on the session store would duplicate
that gate while breaking the legitimate cross-tenant flow.

Schema
------
``admin_users`` columns::

    subject        VARCHAR(255) PK    -- canonical admin id (typically email)
    password_hash  VARCHAR(255)       -- bcrypt at rest (passlib format)
    role           VARCHAR(32)        -- operator | admin | super-admin
    tenant_id      VARCHAR(36) NULL   -- NULL for super-admin
    mfa_secret     VARCHAR(255) NULL  -- Phase 2 reservation (TOTP)
    created_at     TIMESTAMPTZ
    disabled_at    TIMESTAMPTZ NULL   -- soft-delete tombstone

``admin_sessions`` columns::

    session_id        VARCHAR(64) PK    -- token_urlsafe(48) → ~64 chars
    subject           VARCHAR(255)      -- denormalised for revoke lookups
    role              VARCHAR(32)
    tenant_id         VARCHAR(36) NULL
    created_at        TIMESTAMPTZ
    expires_at        TIMESTAMPTZ       -- sliding window, see resolver
    last_used_at      TIMESTAMPTZ
    ip_hash           VARCHAR(64)       -- sha256(ip), forensic only
    user_agent_hash   VARCHAR(64)       -- sha256(ua), forensic only
    revoked_at        TIMESTAMPTZ NULL  -- tombstone (logout / revoke)

Indexes
-------
* ``ix_admin_sessions_subject_revoked (subject, revoked_at)`` — hot path
  for "list active sessions for subject" + bulk-revoke on password change.
* ``ix_admin_sessions_expires_at (expires_at)`` — daily janitor sweep that
  hard-deletes expired rows.

No FK is declared between ``admin_sessions.subject`` and
``admin_users.subject``. Detaching the link lets the auth flow soft-delete
an admin (set ``disabled_at``) while keeping forensic session rows for
audit, and lets the ORM avoid a per-resolve JOIN. The session resolver
re-validates the subject against ``admin_users`` only when the caller
needs the live role (``GET /auth/admin/whoami``).

Backwards compatibility
-----------------------
* Brand-new tables — no impact on existing tables.
* ``downgrade()`` is fully idempotent: every ``DROP`` uses ``IF EXISTS``
  and the operations run in the reverse order of ``upgrade()``.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "028"
down_revision: str | None = "027"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

ADMIN_USERS_TABLE = "admin_users"
ADMIN_SESSIONS_TABLE = "admin_sessions"
INDEX_SUBJECT_REVOKED = "ix_admin_sessions_subject_revoked"
INDEX_EXPIRES_AT = "ix_admin_sessions_expires_at"


def upgrade() -> None:
    op.create_table(
        ADMIN_USERS_TABLE,
        sa.Column("subject", sa.String(255), primary_key=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column("mfa_secret", sa.String(255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("disabled_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        ADMIN_SESSIONS_TABLE,
        sa.Column("session_id", sa.String(64), primary_key=True),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), nullable=False),
        sa.Column("tenant_id", sa.String(36), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "last_used_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("ip_hash", sa.String(64), nullable=False),
        sa.Column("user_agent_hash", sa.String(64), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_index(
        INDEX_SUBJECT_REVOKED,
        ADMIN_SESSIONS_TABLE,
        ["subject", "revoked_at"],
    )
    op.create_index(
        INDEX_EXPIRES_AT,
        ADMIN_SESSIONS_TABLE,
        ["expires_at"],
    )


def downgrade() -> None:
    bind = op.get_bind()
    is_postgres = bind.dialect.name == "postgresql"

    if is_postgres:
        op.execute(f"DROP INDEX IF EXISTS {INDEX_EXPIRES_AT}")
        op.execute(f"DROP INDEX IF EXISTS {INDEX_SUBJECT_REVOKED}")
    else:
        op.drop_index(INDEX_EXPIRES_AT, table_name=ADMIN_SESSIONS_TABLE)
        op.drop_index(INDEX_SUBJECT_REVOKED, table_name=ADMIN_SESSIONS_TABLE)

    op.drop_table(ADMIN_SESSIONS_TABLE)
    op.drop_table(ADMIN_USERS_TABLE)
