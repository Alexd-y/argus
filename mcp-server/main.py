"""ARGUS MCP Server — stub for Phase 1.

Full implementation in Phase 4: FastMCP, stdio transport, 150+ tools.
"""

from fastapi import FastAPI

app = FastAPI(title="ARGUS MCP Server", version="0.1.0")


@app.get("/health")
async def health() -> dict:
    """Health check."""
    return {"status": "ok", "service": "argus-mcp-server"}
