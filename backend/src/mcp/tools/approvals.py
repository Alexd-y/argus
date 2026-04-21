"""MCP ``approvals.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from src.mcp.context import MCPCallContext, MCPContext
from src.mcp.schemas.approval import (
    ApprovalDecideInput,
    ApprovalDecideResult,
    ApprovalListInput,
    ApprovalListResult,
)
from src.mcp.services.approval_service import (
    decide_approval as svc_decide_approval,
    list_approvals as svc_list_approvals,
)
from src.mcp.tenancy import assert_tenant_match
from src.mcp.tools._runtime import run_tool

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)


def register(mcp: "FastMCP") -> None:
    """Bind the ``approvals.*`` tools to ``mcp``."""

    @mcp.tool(
        name="approvals.list",
        description=(
            "List approval requests visible to the authenticated tenant. "
            "Supports filtering by status (pending/granted/denied/revoked/expired) "
            "and tool_id."
        ),
    )
    async def approvals_list(
        payload: ApprovalListInput, ctx: MCPContext | None = None
    ) -> ApprovalListResult:
        async def body(call: MCPCallContext) -> ApprovalListResult:
            assert_tenant_match(call.auth, payload.tenant_id)
            return svc_list_approvals(
                tenant_id=call.auth.tenant_id,
                payload=payload,
            )

        return await run_tool(
            tool_name="approvals.list",
            payload=payload,
            ctx=ctx,
            body=body,
        )

    @mcp.tool(
        name="approvals.decide",
        description=(
            "Record an operator decision (grant / deny / revoke) on an approval "
            "request. The MCP server verifies signatures but never produces them: "
            "GRANT decisions require a pre-computed Ed25519 signature."
        ),
    )
    async def approvals_decide(
        payload: ApprovalDecideInput, ctx: MCPContext | None = None
    ) -> ApprovalDecideResult:
        async def body(call: MCPCallContext) -> ApprovalDecideResult:
            return svc_decide_approval(
                tenant_id=call.auth.tenant_id,
                payload=payload,
                actor=call.auth.user_id or "mcp_anonymous",
            )

        return await run_tool(
            tool_name="approvals.decide",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={
                "request_id": payload.request_id,
                "decision": payload.decision.value,
            },
        )


__all__ = ["register"]
