"""MCP ``policy.*`` and ``scope.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from src.mcp.context import MCPCallContext, MCPContext
from src.mcp.schemas.policy import (
    PolicyEvaluateInput,
    PolicyEvaluateResult,
    ScopeVerifyInput,
    ScopeVerifyResult,
)
from src.mcp.services.policy_service import (
    evaluate_policy as svc_evaluate_policy,
    verify_scope as svc_verify_scope,
)
from src.mcp.tenancy import assert_tenant_match
from src.mcp.tools._runtime import run_tool

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)


def register(mcp: "FastMCP") -> None:
    """Bind the ``policy.*`` and ``scope.*`` tools to ``mcp``."""

    @mcp.tool(
        name="scope.verify",
        description=(
            "Check whether a given target is in the authenticated tenant's "
            "customer scope. Returns the raw ScopeEngine decision plus a "
            "closed-taxonomy failure summary."
        ),
    )
    async def scope_verify(
        payload: ScopeVerifyInput, ctx: MCPContext | None = None
    ) -> ScopeVerifyResult:
        async def body(call: MCPCallContext) -> ScopeVerifyResult:
            assert_tenant_match(call.auth, payload.tenant_id)
            return svc_verify_scope(tenant_id=call.auth.tenant_id, payload=payload)

        return await run_tool(
            tool_name="scope.verify",
            payload=payload,
            ctx=ctx,
            body=body,
        )

    @mcp.tool(
        name="policy.evaluate",
        description=(
            "Run the PolicyEngine against a hypothetical action and return one "
            "of allowed / requires_approval / denied. Used by the LLM to "
            "pre-flight a tool call before invoking ``tool.run.trigger``."
        ),
    )
    async def policy_evaluate(
        payload: PolicyEvaluateInput, ctx: MCPContext | None = None
    ) -> PolicyEvaluateResult:
        async def body(call: MCPCallContext) -> PolicyEvaluateResult:
            return svc_evaluate_policy(tenant_id=call.auth.tenant_id, payload=payload)

        return await run_tool(
            tool_name="policy.evaluate",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={
                "tool_id": payload.tool_id,
                "risk_level": payload.risk_level.value,
            },
        )


__all__ = ["register"]
