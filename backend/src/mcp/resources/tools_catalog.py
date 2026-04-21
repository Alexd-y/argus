"""``argus://catalog/tools`` resource."""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from src.mcp.services.tool_service import list_catalog

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)


def register(mcp: "FastMCP") -> None:
    """Bind the tools-catalog resource to ``mcp``."""

    @mcp.resource(
        "argus://catalog/tools",
        name="argus.catalog.tools",
        title="ARGUS signed tool catalog",
        mime_type="application/json",
        description=(
            "Snapshot of the signed tool catalog (capped at 200 entries). "
            "Sandbox-internal fields (image, command_template, etc.) are stripped."
        ),
    )
    async def tools_catalog_resource() -> str:
        result = list_catalog(limit=200, offset=0)
        payload = {
            "items": [item.model_dump(mode="json") for item in result.items],
            "total": result.total,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


__all__ = ["register"]
