"""``argus://findings/{scan_id}`` resource."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from src.mcp.context import MCPContext, build_call_context
from src.mcp.exceptions import ValidationError
from src.mcp.schemas.finding import FindingFilter
from src.mcp.services.finding_service import list_findings

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)

_MAX_LIMIT = 200
_VALID_SCAN_ID = (8, 64)


def register(mcp: "FastMCP") -> None:
    """Bind the findings resource template to ``mcp``."""

    @mcp.resource(
        "argus://findings/{scan_id}",
        name="argus.findings.scan",
        title="ARGUS findings for a scan",
        mime_type="application/json",
        description=(
            "Paginated findings for the given scan (tenant-scoped; capped at 200 entries)."
        ),
    )
    async def findings_resource(scan_id: str, ctx: MCPContext | None = None) -> str:
        if not scan_id or not (_VALID_SCAN_ID[0] <= len(scan_id) <= _VALID_SCAN_ID[1]):
            raise ValidationError("scan_id must be 8..64 characters long.")
        call = build_call_context(ctx)
        result = await list_findings(
            tenant_id=call.auth.tenant_id,
            scan_id=scan_id,
            filters=FindingFilter(),
            limit=_MAX_LIMIT,
            offset=0,
        )
        payload = {
            "scan_id": scan_id,
            "items": [item.model_dump(mode="json") for item in result.items],
            "total": result.total,
            "next_offset": result.next_offset,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


__all__ = ["register"]
