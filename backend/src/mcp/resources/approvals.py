"""``argus://approvals/pending`` resource."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from src.mcp.context import build_call_context
from src.mcp.schemas.approval import ApprovalListInput
from src.mcp.schemas.common import PaginationInput
from src.mcp.services.approval_service import list_approvals

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)


def register(mcp: "FastMCP") -> None:
    """Bind the pending-approvals resource to ``mcp``."""

    @mcp.resource(
        "argus://approvals/pending",
        name="argus.approvals.pending",
        title="Pending approval queue",
        mime_type="application/json",
        description=(
            "Tenant-scoped pending approval requests (capped at 100). Operators "
            "should poll this resource and submit decisions via approvals.decide."
        ),
    )
    async def approvals_pending_resource() -> str:
        # Resources cannot accept ``ctx`` here without FastMCP misclassifying
        # the URI as a template (empty groupdict → matches() returns falsy).
        # ``build_call_context(None)`` reads from the auth override / static
        # token context — exactly the same path the tools use.
        call = build_call_context(None)
        payload = ApprovalListInput(
            status="pending",
            tool_id=None,
            tenant_id=None,
            pagination=PaginationInput(limit=100, offset=0),
        )
        result = list_approvals(
            tenant_id=call.auth.tenant_id,
            payload=payload,
        )
        body = {
            "items": [item.model_dump(mode="json") for item in result.items],
            "total": result.total,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":"))


__all__ = ["register"]
