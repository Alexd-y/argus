"""H-5: MCP server auth token support."""

from __future__ import annotations

from pathlib import Path

ARGUS_ROOT = Path(__file__).resolve().parents[2]


class TestMcpAuthToken:
    """MCP server must read and enforce MCP_AUTH_TOKEN."""

    def test_mcp_server_file_exists(self) -> None:
        mcp_path = ARGUS_ROOT / "mcp-server" / "argus_mcp.py"
        assert mcp_path.exists(), "mcp-server/argus_mcp.py must exist"

    def test_mcp_auth_token_env_read(self) -> None:
        mcp_path = ARGUS_ROOT / "mcp-server" / "argus_mcp.py"
        content = mcp_path.read_text(encoding="utf-8")
        assert "MCP_AUTH_TOKEN" in content, "MCP server must reference MCP_AUTH_TOKEN"

    def test_mcp_auth_token_bearer_check(self) -> None:
        mcp_path = ARGUS_ROOT / "mcp-server" / "argus_mcp.py"
        content = mcp_path.read_text(encoding="utf-8")
        assert "Bearer" in content, "MCP server must validate Bearer token"

    def test_mcp_binds_localhost_without_token(self) -> None:
        """Without MCP_AUTH_TOKEN, server should bind to 127.0.0.1 only."""
        mcp_path = ARGUS_ROOT / "mcp-server" / "argus_mcp.py"
        content = mcp_path.read_text(encoding="utf-8")
        assert "127.0.0.1" in content, "MCP server must default to localhost binding"
