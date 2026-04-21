"""Service layer used by MCP tools.

Each module in this package exposes a small, framework-free async function
or class that the MCP tools call. This keeps the tool definitions in
:mod:`src.mcp.tools` thin and free of SQL / FastAPI imports — the same
service modules can also be reused from CLI scripts and tests.
"""
