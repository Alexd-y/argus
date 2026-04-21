"""MCP tool implementations (one module per Backlog/dev1_md §13 sub-area).

Each module exposes a ``register(mcp)`` function that the server calls at
startup to bind the tools to the FastMCP application. Splitting the tools
up by domain keeps the module sizes small and lets us write focused unit
tests per file.
"""

from mcp.server.fastmcp import FastMCP

from src.mcp.tools import (
    approvals as approvals_tools,
)
from src.mcp.tools import (
    findings as findings_tools,
)
from src.mcp.tools import (
    policy as policy_tools,
)
from src.mcp.tools import (
    reports as reports_tools,
)
from src.mcp.tools import (
    scans as scans_tools,
)
from src.mcp.tools import (
    tool_catalog as tool_catalog_tools,
)


def register_all(mcp: FastMCP) -> None:
    """Register every MCP tool with ``mcp`` (a :class:`FastMCP` instance)."""
    scans_tools.register(mcp)
    findings_tools.register(mcp)
    approvals_tools.register(mcp)
    tool_catalog_tools.register(mcp)
    reports_tools.register(mcp)
    policy_tools.register(mcp)


__all__ = [
    "approvals_tools",
    "findings_tools",
    "policy_tools",
    "register_all",
    "reports_tools",
    "scans_tools",
    "tool_catalog_tools",
]
