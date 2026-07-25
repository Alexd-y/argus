"""053 — auth-bootstrap SELECT policy on ``users`` (unblocks SEC-002 FORCE RLS).

Revision ID: 053
Revises: 052
Create Date: 2026-07-25

Migration ``052`` adds ``FORCE ROW LEVEL SECURITY`` to ``users`` (among other
core tenant tables). The ``tenant_isolation`` policy created in ``002`` reads
``current_setting('app.current_tenant_id', true)`` and is *never satisfied* when
that GUC is unset, so under ``FORCE`` the pre-authentication login lookup in
``src/api/routers/auth.py`` — ``SELECT ... FROM users WHERE email = ...`` on a
session that has no tenant context yet — returns zero rows and **every login
fails silently** (P0 blocker recorded in ``docs/rls-force-052-checklist.md`` §3.1).

The tenant a user belongs to is only known *after* the row is found, so the
login path cannot set the GUC beforehand. This migration installs a second,
permissive, **SELECT-only** policy on ``users`` that is satisfied exactly when
no tenant context is set. PostgreSQL OR-combines permissive policies per
command, so the resulting behaviour is:

* tenant-scoped session (GUC set): only ``tenant_isolation`` can match — a
  caller still sees only its own tenant's users (isolation preserved);
* pre-auth login / cross-tenant admin session (GUC unset): the bootstrap policy
  matches — the email lookup (``auth.py``) and the admin user listing
  (``api/routers/admin.py``) can read ``users``.

INSERT / UPDATE / DELETE are deliberately left untouched: only the ``FOR ALL``
``tenant_isolation`` policy governs writes, so every write to ``users`` still
requires a matching tenant context (there is no runtime path in ``src/`` that
writes ``users`` without one — user rows are seeded out of band).

Security rationale: ``users`` is the authentication bootstrap table. Permitting
a tenant-agnostic *read* when — and only when — no tenant context is present is
the standard pattern for pre-auth credential lookup. It does not weaken
isolation for any request that has resolved a tenant, and under SEC-001 every
main-API request resolves a tenant and therefore sets the GUC.

Ordering: apply together with ``052`` (``alembic upgrade head`` runs both before
the app serves traffic). SQLite (smoke round-trip) has no RLS, so this is a
no-op there and the migration round-trips cleanly.
"""

from collections.abc import Sequence

from alembic import op

revision: str = "053"
down_revision: str | None = "052"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TABLE: str = "users"
_POLICY: str = "users_auth_bootstrap"


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    # Idempotent: drop any prior instance before recreating.
    op.execute(f'DROP POLICY IF EXISTS {_POLICY} ON "{_TABLE}"')
    op.execute(
        f"""
        CREATE POLICY {_POLICY} ON "{_TABLE}"
        FOR SELECT
        USING (current_setting('app.current_tenant_id', true) IS NULL)
        """
    )


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return

    op.execute(f'DROP POLICY IF EXISTS {_POLICY} ON "{_TABLE}"')
