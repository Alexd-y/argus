"""``argus://reports/{report_id}`` resource."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from src.mcp.context import MCPContext, build_call_context
from src.mcp.exceptions import ValidationError
from src.mcp.schemas.report import ReportFormat
from src.mcp.services.report_service import get_report_download

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)

_VALID_REPORT_ID = (8, 64)


def register(mcp: "FastMCP") -> None:
    """Bind the reports resource template to ``mcp``."""

    @mcp.resource(
        "argus://reports/{report_id}",
        name="argus.reports.report",
        title="ARGUS report metadata + presigned URL",
        mime_type="application/json",
        description=(
            "Tenant-scoped report metadata and short-lived presigned URL. "
            "Defaults to JSON format."
        ),
    )
    async def reports_resource(report_id: str, ctx: MCPContext | None = None) -> str:
        if not report_id or not (
            _VALID_REPORT_ID[0] <= len(report_id) <= _VALID_REPORT_ID[1]
        ):
            raise ValidationError("report_id must be 8..64 characters long.")
        call = build_call_context(ctx)
        download = await get_report_download(
            tenant_id=call.auth.tenant_id,
            report_id=report_id,
            format=ReportFormat.JSON,
        )
        return json.dumps(
            download.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        )


__all__ = ["register"]
