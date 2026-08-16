"""MCP ``scan.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from src.mcp.context import MCPCallContext, MCPContext
from src.mcp.exceptions import ApprovalRequiredError, ValidationError
from src.mcp.schemas.common import ToolResultStatus
from src.mcp.schemas.scan import (
    ScanCancelInput,
    ScanCancelResult,
    ScanCoverageInput,
    ScanCoverageResult,
    ScanCreateInput,
    ScanCreateResult,
    ScanPlanInput,
    ScanPlanResult,
    ScanProfile,
    ScanStatusInput,
    ScanStatusResult,
)
from src.mcp.services.scan_service import (
    cancel_scan as svc_cancel_scan,
)
from src.mcp.services.scan_service import (
    enqueue_scan as svc_enqueue_scan,
)
from src.mcp.services.scan_service import (
    get_scan_coverage as svc_get_scan_coverage,
)
from src.mcp.services.scan_service import (
    get_scan_plan as svc_get_scan_plan,
)
from src.mcp.services.scan_service import (
    get_scan_status as svc_get_scan_status,
)
from src.mcp.services.scan_service import (
    lab_lease_skips_deep_justification,
)
from src.mcp.tools._runtime import run_tool

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)


def register(mcp: FastMCP) -> None:
    """Bind the ``scan.*`` tools to ``mcp``."""

    @mcp.tool(
        name="scan.create",
        description=(
            "Enqueue a new pentest scan for the authenticated tenant. "
            "Returns the new scan_id and high-level lifecycle state. "
            "execution_mode is distinct from profile (scan depth); "
            "ScanProfile.QUICK is depth, not Quick execution mode. "
            "DEEP profile requires a justification unless a valid lab lease is present. "
            "Raw argv/command strings are rejected."
        ),
    )
    async def scan_create(
        payload: ScanCreateInput, ctx: MCPContext | None = None
    ) -> ScanCreateResult:
        async def body(call: MCPCallContext) -> ScanCreateResult:
            lab_ok = lab_lease_skips_deep_justification(
                payload.scan_options,
                tenant_id=call.auth.tenant_id,
            )
            if (
                payload.profile is ScanProfile.DEEP
                and not lab_ok
                and not (payload.justification and payload.justification.strip())
            ):
                raise ApprovalRequiredError(
                    "Deep scans require a justification (>=10 characters)."
                )
            if (
                payload.justification is not None
                and len(payload.justification.strip()) < 10
            ):
                raise ValidationError("justification must be at least 10 characters.")
            return await svc_enqueue_scan(
                tenant_id=call.auth.tenant_id,
                user_id=call.auth.user_id or "mcp_anonymous",
                payload=payload,
            )

        return await run_tool(
            tool_name="scan.create",
            payload=payload,
            ctx=ctx,
            body=body,
        )

    @mcp.tool(
        name="scan.status",
        description=(
            "Return the current status, progress, and severity counts for a "
            "scan owned by the authenticated tenant."
        ),
    )
    async def scan_status(
        payload: ScanStatusInput, ctx: MCPContext | None = None
    ) -> ScanStatusResult:
        async def body(call: MCPCallContext) -> ScanStatusResult:
            return await svc_get_scan_status(
                tenant_id=call.auth.tenant_id,
                scan_id=payload.scan_id,
            )

        return await run_tool(
            tool_name="scan.status",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={"scan_id": payload.scan_id},
        )

    @mcp.tool(
        name="scan.cancel",
        description=(
            "Cancel an in-progress scan owned by the authenticated tenant. "
            "Requires an operator-supplied reason that is recorded in the audit log."
        ),
    )
    async def scan_cancel(
        payload: ScanCancelInput, ctx: MCPContext | None = None
    ) -> ScanCancelResult:
        async def body(call: MCPCallContext) -> ScanCancelResult:
            new_state = await svc_cancel_scan(
                tenant_id=call.auth.tenant_id,
                scan_id=payload.scan_id,
                reason=payload.reason,
            )
            return ScanCancelResult(
                scan_id=payload.scan_id,
                status=ToolResultStatus.SUCCESS,
                new_state=new_state,
            )

        return await run_tool(
            tool_name="scan.cancel",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={"scan_id": payload.scan_id},
        )

    @mcp.tool(
        name="scan.plan",
        description=(
            "Return the latest Quick execution-mode plan for a tenant-owned scan. "
            "Non-quick scans return plan_not_applicable. Never includes argv/command."
        ),
    )
    async def scan_plan(
        payload: ScanPlanInput, ctx: MCPContext | None = None
    ) -> ScanPlanResult:
        async def body(call: MCPCallContext) -> ScanPlanResult:
            return await svc_get_scan_plan(
                tenant_id=call.auth.tenant_id,
                scan_id=payload.scan_id,
            )

        return await run_tool(
            tool_name="scan.plan",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={"scan_id": payload.scan_id},
        )

    @mcp.tool(
        name="scan.coverage",
        description=(
            "Return coverage records for a tenant-owned scan, including reason_code. "
            "Absence of a finding is not coverage."
        ),
    )
    async def scan_coverage(
        payload: ScanCoverageInput, ctx: MCPContext | None = None
    ) -> ScanCoverageResult:
        async def body(call: MCPCallContext) -> ScanCoverageResult:
            return await svc_get_scan_coverage(
                tenant_id=call.auth.tenant_id,
                scan_id=payload.scan_id,
            )

        return await run_tool(
            tool_name="scan.coverage",
            payload=payload,
            ctx=ctx,
            body=body,
            extra_audit_payload={"scan_id": payload.scan_id},
        )


__all__ = ["register"]
