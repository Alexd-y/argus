"""MCP ``report.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from src.mcp.context import MCPCallContext, MCPContext
from src.mcp.schemas.report import (
    ReportDownloadInput,
    ReportDownloadResult,
    ReportGenerateInput,
    ReportGenerateResult,
)
from src.mcp.services.report_service import (
    get_report_download as svc_get_report_download,
    request_report_generation as svc_request_report_generation,
)
from src.mcp.tools._runtime import run_tool

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)


def register(mcp: "FastMCP") -> None:
    """Bind the ``report.*`` tools to ``mcp``."""

    @mcp.tool(
        name="report.generate",
        description=(
            "Queue a report (Midgard / Asgard / Valhalla cascade) for a scan "
            "owned by the authenticated tenant. The MCP server only enqueues "
            "the generation job — poll ``report.download`` for the artifact."
        ),
    )
    async def report_generate(
        payload: ReportGenerateInput, ctx: MCPContext | None = None
    ) -> ReportGenerateResult:
        async def body(call: MCPCallContext) -> ReportGenerateResult:
            return await svc_request_report_generation(
                tenant_id=call.auth.tenant_id,
                scan_id=payload.scan_id,
                tier=payload.tier,
                format=payload.format,
            )

        return await run_tool(
            tool_name="report.generate",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={
                "scan_id": payload.scan_id,
                "tier": payload.tier.value,
                "format": payload.format.value,
            },
        )

    @mcp.tool(
        name="report.download",
        description=(
            "Return a short-lived presigned URL and SHA-256 for a report owned by "
            "the authenticated tenant. The MCP server NEVER streams artifact bytes "
            "in the JSON-RPC response."
        ),
    )
    async def report_download(
        payload: ReportDownloadInput, ctx: MCPContext | None = None
    ) -> ReportDownloadResult:
        async def body(call: MCPCallContext) -> ReportDownloadResult:
            return await svc_get_report_download(
                tenant_id=call.auth.tenant_id,
                report_id=payload.report_id,
                format=payload.format,
            )

        return await run_tool(
            tool_name="report.download",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={
                "report_id": payload.report_id,
                "format": payload.format.value,
            },
        )


__all__ = ["register"]
