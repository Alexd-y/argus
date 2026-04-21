"""MCP ``findings.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from src.mcp.context import MCPCallContext, MCPContext
from src.mcp.schemas.common import ToolResultStatus
from src.mcp.schemas.finding import (
    FindingDetail,
    FindingGetInput,
    FindingListInput,
    FindingListResult,
    FindingMarkFalsePositiveInput,
    FindingMarkResult,
)
from src.mcp.services.finding_service import (
    get_finding as svc_get_finding,
    list_findings as svc_list_findings,
    mark_false_positive as svc_mark_false_positive,
)
from src.mcp.tools._runtime import run_tool

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)


def register(mcp: "FastMCP") -> None:
    """Bind the ``findings.*`` tools to ``mcp``."""

    @mcp.tool(
        name="findings.list",
        description=(
            "List findings for a scan owned by the authenticated tenant. "
            "Supports filtering by severity, CWE, OWASP category, and "
            "confidence; returns paginated summaries."
        ),
    )
    async def findings_list(
        payload: FindingListInput, ctx: MCPContext | None = None
    ) -> FindingListResult:
        async def body(call: MCPCallContext) -> FindingListResult:
            return await svc_list_findings(
                tenant_id=call.auth.tenant_id,
                scan_id=payload.scan_id,
                filters=payload.filters,
                limit=payload.pagination.limit,
                offset=payload.pagination.offset,
            )

        return await run_tool(
            tool_name="findings.list",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={"scan_id": payload.scan_id},
        )

    @mcp.tool(
        name="findings.get",
        description=(
            "Return a single finding (with redacted evidence and proof-of-concept) "
            "owned by the authenticated tenant."
        ),
    )
    async def findings_get(
        payload: FindingGetInput, ctx: MCPContext | None = None
    ) -> FindingDetail:
        async def body(call: MCPCallContext) -> FindingDetail:
            return await svc_get_finding(
                tenant_id=call.auth.tenant_id,
                finding_id=payload.finding_id,
            )

        return await run_tool(
            tool_name="findings.get",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={"finding_id": payload.finding_id},
        )

    @mcp.tool(
        name="findings.mark_false_positive",
        description=(
            "Mark a finding as a false positive (with operator justification). "
            "Idempotent — returning ``unchanged`` when already flagged."
        ),
    )
    async def findings_mark_false_positive(
        payload: FindingMarkFalsePositiveInput, ctx: MCPContext | None = None
    ) -> FindingMarkResult:
        async def body(call: MCPCallContext) -> FindingMarkResult:
            updated = await svc_mark_false_positive(
                tenant_id=call.auth.tenant_id,
                finding_id=payload.finding_id,
                reason=payload.reason,
                actor=call.auth.user_id or "mcp_anonymous",
            )
            return FindingMarkResult(
                finding_id=payload.finding_id,
                status=(
                    ToolResultStatus.SUCCESS if updated else ToolResultStatus.UNCHANGED
                ),
            )

        return await run_tool(
            tool_name="findings.mark_false_positive",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={"finding_id": payload.finding_id},
        )


__all__ = ["register"]
