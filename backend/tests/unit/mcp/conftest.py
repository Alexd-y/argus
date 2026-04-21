"""Shared fixtures for the ``backend/tests/unit/mcp`` subtree.

The MCP layer is intentionally framework-agnostic: every test in this folder
exercises a pure-Python entry point (Pydantic schemas, ``MCPAuditLogger``,
``authenticate``, the service layer) and asserts strict tenant isolation,
audit-log emission, and closed-taxonomy error mapping.

Fixtures live here because:

1. The audit logger is a process-wide singleton via
   :func:`src.mcp.context.set_audit_logger`. We swap it for a fresh
   in-memory instance per test so audit events can be inspected
   deterministically.
2. The auth context override (``set_auth_override``) is the canonical way
   to bypass header parsing in unit tests; we expose a fixture that
   resets it after every test, even on failure.
3. Every test gets a ``tenant_id`` UUID and a sibling ``other_tenant_id``
   so cross-tenant tests can assert :class:`TenantMismatchError` without
   ad-hoc constants.

Important: ``src.db.session`` builds a SQLAlchemy engine at *import* time
with PostgreSQL-only pool kwargs (``pool_size``, ``max_overflow``).  The
parent unit-test conftest sets ``DATABASE_URL=sqlite+aiosqlite:///:memory:``
which blows up that constructor.  The MCP suite imports
``src.mcp.tools._runtime`` -> ``src.mcp.services.finding_service`` ->
``src.db.session`` so we *must* override the DSN to a Postgres-shaped
string before any ``src.*`` import.  No real connection is opened — the
engine is initialised lazily on first ``await engine.begin()``.
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Override the parent unit-test default *before* any src.* import lands.
# ``setdefault`` would lose to the parent ``unit/conftest.py`` which already
# set DATABASE_URL=sqlite+aiosqlite:///:memory:, so we use a hard assignment.
# ---------------------------------------------------------------------------
os.environ["DATABASE_URL"] = (
    "postgresql+asyncpg://mcp-unit-test:no-password@localhost:5432/mcp_test"
)

from collections.abc import Iterator  # noqa: E402
from uuid import UUID, uuid4  # noqa: E402

import pytest  # noqa: E402

from src.mcp.audit_logger import MCPAuditLogger, make_default_audit_logger  # noqa: E402
from src.mcp.auth import MCPAuthContext  # noqa: E402
from src.mcp.context import (  # noqa: E402
    set_audit_logger,
    set_auth_override,
    set_notification_dispatcher,
    set_rate_limiter,
)


@pytest.fixture()
def tenant_id() -> str:
    """Stable UUID-shaped tenant identifier for the test session."""
    return str(uuid4())


@pytest.fixture()
def other_tenant_id() -> str:
    """A *second* tenant id distinct from :func:`tenant_id`."""
    return str(uuid4())


@pytest.fixture()
def actor_id() -> str:
    """Caller identity used by audit assertions."""
    return "mcp-unit-test-actor"


@pytest.fixture()
def auth_ctx(tenant_id: str, actor_id: str) -> MCPAuthContext:
    """Authenticated context used by MCP tool / resource tests."""
    return MCPAuthContext(
        user_id=actor_id,
        tenant_id=tenant_id,
        method="static_token",
        is_admin=False,
    )


@pytest.fixture()
def admin_auth_ctx(tenant_id: str) -> MCPAuthContext:
    """Admin-flavoured authenticated context."""
    return MCPAuthContext(
        user_id="argus-admin",
        tenant_id=tenant_id,
        method="api_key",
        is_admin=True,
    )


@pytest.fixture()
def cross_tenant_auth_ctx(other_tenant_id: str) -> MCPAuthContext:
    """Authenticated context for the *other* tenant — used to drive cross-tenant denies."""
    return MCPAuthContext(
        user_id="other-tenant-actor",
        tenant_id=other_tenant_id,
        method="static_token",
        is_admin=False,
    )


@pytest.fixture()
def audit_logger() -> MCPAuditLogger:
    """Fresh in-memory audit logger per test."""
    return make_default_audit_logger()


@pytest.fixture(autouse=True)
def _reset_mcp_globals(audit_logger: MCPAuditLogger) -> Iterator[None]:
    """Reset audit / auth process-wide singletons before and after every test.

    Without this guard a prior test would leak its auth override / audit sink
    into the next test, producing flaky cross-tenant assertions.
    """
    set_auth_override(None)
    set_audit_logger(audit_logger)
    set_rate_limiter(None)
    set_notification_dispatcher(None)
    try:
        yield
    finally:
        set_auth_override(None)
        set_audit_logger(None)
        set_rate_limiter(None)
        set_notification_dispatcher(None)


def assert_uuid(value: str) -> UUID:
    """Helper: assert ``value`` is a valid UUID string and return it."""
    return UUID(value)
