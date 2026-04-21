"""MCP resources (Backlog/dev1_md §13).

Resources are *read-only* views the LLM can subscribe to with a stable URI
scheme. We expose four resources:

* ``argus://catalog/tools`` — signed tool catalog snapshot.
* ``argus://findings/{scan_id}`` — paginated findings for a scan.
* ``argus://reports/{report_id}`` — report metadata + presigned URLs.
* ``argus://approvals/pending`` — pending approval queue for the tenant.
"""

from mcp.server.fastmcp import FastMCP

from src.mcp.resources import (
    approvals as approvals_resources,
)
from src.mcp.resources import (
    findings as findings_resources,
)
from src.mcp.resources import (
    reports as reports_resources,
)
from src.mcp.resources import (
    tools_catalog as tools_catalog_resources,
)


def register_all(mcp: FastMCP) -> None:
    """Register every MCP resource with ``mcp``."""
    tools_catalog_resources.register(mcp)
    findings_resources.register(mcp)
    reports_resources.register(mcp)
    approvals_resources.register(mcp)


__all__ = [
    "approvals_resources",
    "findings_resources",
    "register_all",
    "reports_resources",
    "tools_catalog_resources",
]
