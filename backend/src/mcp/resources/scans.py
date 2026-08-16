"""``argus://scans/{scan_id}/plan`` and ``argus://scans/{scan_id}/coverage``."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from src.mcp.context import MCPContext, build_call_context
from src.mcp.exceptions import ValidationError
from src.mcp.services.scan_service import get_scan_coverage, get_scan_plan

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)

_VALID_SCAN_ID = (8, 64)


def _validate_scan_id(scan_id: str) -> None:
    if not scan_id or not (_VALID_SCAN_ID[0] <= len(scan_id) <= _VALID_SCAN_ID[1]):
        raise ValidationError("scan_id must be 8..64 characters long.")


def register(mcp: FastMCP) -> None:
    """Bind Quick plan/coverage resources to ``mcp``."""

    @mcp.resource(
        "argus://scans/{scan_id}/plan",
        name="argus.scans.plan",
        title="ARGUS Quick scan plan",
        mime_type="application/json",
        description=(
            "Latest Quick execution-mode plan for the scan (tenant-scoped). "
            "Non-quick scans are not applicable."
        ),
    )
    async def scan_plan_resource(scan_id: str, ctx: MCPContext | None = None) -> str:
        _validate_scan_id(scan_id)
        call = build_call_context(ctx)
        result = await get_scan_plan(tenant_id=call.auth.tenant_id, scan_id=scan_id)
        return json.dumps(result.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))

    @mcp.resource(
        "argus://scans/{scan_id}/coverage",
        name="argus.scans.coverage",
        title="ARGUS scan coverage",
        mime_type="application/json",
        description=(
            "Coverage records for the scan including reason_code (tenant-scoped). "
            "Absence of a finding is not coverage."
        ),
    )
    async def scan_coverage_resource(scan_id: str, ctx: MCPContext | None = None) -> str:
        _validate_scan_id(scan_id)
        call = build_call_context(ctx)
        result = await get_scan_coverage(tenant_id=call.auth.tenant_id, scan_id=scan_id)
        return json.dumps(result.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


__all__ = ["register"]
