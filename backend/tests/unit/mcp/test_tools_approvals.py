"""Unit tests for MCP ``approvals.*`` tools (Backlog/dev1_md §13).

The approval service ships with an in-memory repository so the tests run
without a DB. We focus on:

* Tenant-scoping — cross-tenant attempts raise :class:`TenantMismatchError`.
* Listing returns paginated summaries.
* ``approvals.decide`` enforces signature / justification rules per
  decision action.
* All decisions are audit-logged with the ``request_id`` extra payload.

The tests bypass FastMCP's ``ToolError`` wrapping by invoking the
registered tool's underlying coroutine directly so the closed-taxonomy
:class:`MCPError` instances propagate as-is.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from mcp.server.fastmcp import FastMCP

from src.mcp.audit_logger import MCPAuditLogger
from src.mcp.auth import MCPAuthContext
from src.mcp.context import set_audit_logger, set_auth_override
from src.mcp.exceptions import (
    ResourceNotFoundError,
    TenantMismatchError,
    ValidationError,
)
from src.mcp.schemas.approval import (
    ApprovalDecideInput,
    ApprovalDecideResult,
    ApprovalDecisionAction,
    ApprovalListInput,
    ApprovalListResult,
)
from src.mcp.services.approval_service import (
    InMemoryApprovalRepository,
    StoredApproval,
    set_approval_repository,
)
from src.mcp.tools import approvals as approvals_tools


def _drain_events(audit_logger: MCPAuditLogger) -> list[object]:
    sink = audit_logger.audit_logger.sink
    events: list[object] = []
    for tenant_events in sink._events.values():  # type: ignore[attr-defined]
        events.extend(tenant_events)
    events.sort(key=lambda e: e.occurred_at)  # type: ignore[attr-defined]
    return events


@pytest.fixture()
def repo() -> InMemoryApprovalRepository:
    """Fresh repository per test."""
    instance = InMemoryApprovalRepository()
    set_approval_repository(instance)
    return instance


@pytest.fixture()
def app(auth_ctx: MCPAuthContext, audit_logger: MCPAuditLogger) -> FastMCP:
    set_auth_override(auth_ctx)
    set_audit_logger(audit_logger)
    instance = FastMCP(name="argus-approvals-test")
    approvals_tools.register(instance)
    return instance


def _seed(
    repo: InMemoryApprovalRepository,
    *,
    request_id: str,
    tenant_id: str,
    status: str = "pending",
    tool_id: str = "demo_tool",
) -> StoredApproval:
    now = datetime.now(timezone.utc)
    approval = StoredApproval(
        request_id=request_id,
        tenant_id=tenant_id,
        tool_id=tool_id,
        target="https://example.com",
        action="high",
        status=status,
        created_at=now,
        expires_at=now + timedelta(hours=24),
    )
    repo.add(approval)
    return approval


def _tool_fn(app: FastMCP, name: str):
    return app._tool_manager._tools[name].fn  # type: ignore[attr-defined]


def _call(app: FastMCP, name: str, payload: object) -> object:
    return asyncio.run(_tool_fn(app, name)(payload=payload))


class TestApprovalsList:
    def test_returns_pending_for_authenticated_tenant(
        self,
        app: FastMCP,
        repo: InMemoryApprovalRepository,
        tenant_id: str,
        other_tenant_id: str,
    ) -> None:
        _seed(repo, request_id="req-pending-tenant1", tenant_id=tenant_id)
        _seed(repo, request_id="req-pending-tenant2", tenant_id=other_tenant_id)
        result = _call(app, "approvals.list", ApprovalListInput(status="pending"))
        assert isinstance(result, ApprovalListResult)
        assert result.total == 1
        assert result.items[0].request_id == "req-pending-tenant1"

    def test_filters_by_tool_id(
        self,
        app: FastMCP,
        repo: InMemoryApprovalRepository,
        tenant_id: str,
    ) -> None:
        _seed(
            repo,
            request_id="req-pending-nuclei",
            tenant_id=tenant_id,
            tool_id="nuclei",
        )
        _seed(
            repo,
            request_id="req-pending-ffuf",
            tenant_id=tenant_id,
            tool_id="ffuf",
        )
        result = _call(
            app,
            "approvals.list",
            ApprovalListInput(status="pending", tool_id="nuclei"),
        )
        assert isinstance(result, ApprovalListResult)
        assert result.total == 1
        assert result.items[0].tool_id == "nuclei"

    def test_cross_tenant_id_in_payload_raises_mismatch(
        self,
        app: FastMCP,
        other_tenant_id: str,
    ) -> None:
        with pytest.raises(TenantMismatchError):
            _call(
                app,
                "approvals.list",
                ApprovalListInput(tenant_id=other_tenant_id, status="pending"),
            )


class TestApprovalsDecideValidation:
    def test_grant_without_signature_rejected(self, app: FastMCP) -> None:
        with pytest.raises(ValidationError):
            _call(
                app,
                "approvals.decide",
                ApprovalDecideInput(
                    request_id="req-known-1",
                    decision=ApprovalDecisionAction.GRANT,
                ),
            )

    def test_deny_without_justification_rejected(self, app: FastMCP) -> None:
        with pytest.raises(ValidationError):
            _call(
                app,
                "approvals.decide",
                ApprovalDecideInput(
                    request_id="req-known-1",
                    decision=ApprovalDecisionAction.DENY,
                ),
            )

    def test_revoke_with_short_justification_rejected(self, app: FastMCP) -> None:
        with pytest.raises(ValidationError):
            _call(
                app,
                "approvals.decide",
                ApprovalDecideInput(
                    request_id="req-known-1",
                    decision=ApprovalDecisionAction.REVOKE,
                    justification="no",
                ),
            )


class TestApprovalsDecideHappyPath:
    def test_deny_records_new_status(
        self,
        app: FastMCP,
        repo: InMemoryApprovalRepository,
        tenant_id: str,
        audit_logger: MCPAuditLogger,
    ) -> None:
        _seed(repo, request_id="req-pending-deny", tenant_id=tenant_id)
        result = _call(
            app,
            "approvals.decide",
            ApprovalDecideInput(
                request_id="req-pending-deny",
                decision=ApprovalDecisionAction.DENY,
                justification="Out of scope per customer policy.",
            ),
        )
        assert isinstance(result, ApprovalDecideResult)
        assert result.new_status == "denied"
        events = _drain_events(audit_logger)
        assert events[-1].payload["request_id"] == "req-pending-deny"  # type: ignore[attr-defined]
        assert events[-1].payload["decision"] == "deny"  # type: ignore[attr-defined]

    def test_grant_with_signature_records_status(
        self,
        app: FastMCP,
        repo: InMemoryApprovalRepository,
        tenant_id: str,
    ) -> None:
        _seed(repo, request_id="req-pending-grant", tenant_id=tenant_id)
        signature = "A" * 86
        public_key = "0123456789abcdef"
        result = _call(
            app,
            "approvals.decide",
            ApprovalDecideInput(
                request_id="req-pending-grant",
                decision=ApprovalDecisionAction.GRANT,
                signature_b64=signature,
                public_key_id=public_key,
            ),
        )
        assert isinstance(result, ApprovalDecideResult)
        assert result.new_status == "granted"

    def test_decision_for_other_tenant_returns_not_found(
        self,
        app: FastMCP,
        repo: InMemoryApprovalRepository,
        other_tenant_id: str,
    ) -> None:
        _seed(repo, request_id="req-other-tenant", tenant_id=other_tenant_id)
        with pytest.raises(ResourceNotFoundError):
            _call(
                app,
                "approvals.decide",
                ApprovalDecideInput(
                    request_id="req-other-tenant",
                    decision=ApprovalDecisionAction.DENY,
                    justification="Out of scope per customer policy.",
                ),
            )
