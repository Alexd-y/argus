"""Shared fixtures for ``backend/tests/mcp``.

Shadows the root ``override_auth`` fixture so these tests never boot the
FastAPI app. Sets an in-memory SQLite DSN before ``src.*`` imports (no live
connection — services mock ``async_session_factory``).
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from uuid import uuid4

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ.setdefault("DEBUG", "true")
os.environ.setdefault("JWT_SECRET", "test-secret-not-for-prod-but-required-by-settings")
os.environ.setdefault("ARGUS_TEST_MODE", "1")

import pytest  # noqa: E402

from src.mcp.audit_logger import MCPAuditLogger, make_default_audit_logger  # noqa: E402
from src.mcp.auth import MCPAuthContext  # noqa: E402
from src.mcp.context import (  # noqa: E402
    set_audit_logger,
    set_auth_override,
    set_notification_dispatcher,
    set_rate_limiter,
)


@pytest.fixture(autouse=True)
def override_auth() -> Iterator[None]:
    """Do not boot FastAPI ``app`` — MCP tests call tools/services directly."""
    yield


@pytest.fixture()
def tenant_id() -> str:
    return str(uuid4())


@pytest.fixture()
def actor_id() -> str:
    return "mcp-quick-007-actor"


@pytest.fixture()
def auth_ctx(tenant_id: str, actor_id: str) -> MCPAuthContext:
    return MCPAuthContext(
        user_id=actor_id,
        tenant_id=tenant_id,
        method="static_token",
        is_admin=False,
    )


@pytest.fixture()
def audit_logger() -> MCPAuditLogger:
    return make_default_audit_logger()


@pytest.fixture(autouse=True)
def _reset_mcp_globals(audit_logger: MCPAuditLogger) -> Iterator[None]:
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
