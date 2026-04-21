"""MCP ``tool.catalog.*`` and ``tool.run.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from src.mcp.context import MCPCallContext, MCPContext
from src.mcp.schemas.tool_run import (
    ToolCatalogListInput,
    ToolCatalogListResult,
    ToolRunStatusInput,
    ToolRunStatusResult,
    ToolRunTriggerInput,
    ToolRunTriggerResult,
)
from src.mcp.services.tool_service import (
    get_tool_run_status as svc_get_tool_run_status,
    list_catalog as svc_list_catalog,
    trigger_tool_run as svc_trigger_tool_run,
)
from src.mcp.tools._runtime import run_tool

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)


def register(mcp: "FastMCP") -> None:
    """Bind the ``tool.catalog.*`` and ``tool.run.*`` tools to ``mcp``."""

    @mcp.tool(
        name="tool.catalog.list",
        description=(
            "List tools from the signed catalog, optionally filtered by category, "
            "risk level, or approval requirement. The catalog is loaded from the "
            "process-wide signed registry (sandbox-internal fields are stripped)."
        ),
    )
    async def tool_catalog_list(
        payload: ToolCatalogListInput, ctx: MCPContext | None = None
    ) -> ToolCatalogListResult:
        async def body(call: MCPCallContext) -> ToolCatalogListResult:
            return svc_list_catalog(
                category=payload.category,
                risk_level=payload.risk_level,
                requires_approval=payload.requires_approval,
                limit=payload.pagination.limit,
                offset=payload.pagination.offset,
            )

        return await run_tool(
            tool_name="tool.catalog.list",
            payload=payload,
            ctx=ctx,
            body=body,
        )

    @mcp.tool(
        name="tool.run.trigger",
        description=(
            "Trigger an ad-hoc tool run for the authenticated tenant. HIGH or "
            "DESTRUCTIVE risk tools are NEVER executed inline — instead they "
            "create an approval request and return ``status=approval_pending``."
        ),
    )
    async def tool_run_trigger(
        payload: ToolRunTriggerInput, ctx: MCPContext | None = None
    ) -> ToolRunTriggerResult:
        async def body(call: MCPCallContext) -> ToolRunTriggerResult:
            return svc_trigger_tool_run(
                payload=payload,
                actor=call.auth.user_id or "mcp_anonymous",
                tenant_id=call.auth.tenant_id,
            )

        return await run_tool(
            tool_name="tool.run.trigger",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={
                "tool_id": payload.tool_id,
                "target_redacted": "true",
            },
        )

    @mcp.tool(
        name="tool.run.status",
        description=(
            "Return the lifecycle state of an ad-hoc tool run owned by the "
            "authenticated tenant."
        ),
    )
    async def tool_run_status(
        payload: ToolRunStatusInput, ctx: MCPContext | None = None
    ) -> ToolRunStatusResult:
        async def body(call: MCPCallContext) -> ToolRunStatusResult:
            return svc_get_tool_run_status(
                tenant_id=call.auth.tenant_id,
                tool_run_id=payload.tool_run_id,
            )

        return await run_tool(
            tool_name="tool.run.status",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={"tool_run_id": payload.tool_run_id},
        )


__all__ = ["register"]
