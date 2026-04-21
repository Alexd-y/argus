"""FIX-005: MCP fetch uses httpx as primary, falls back to MCP on failure."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest


class TestFetchUrlMcpHttpxPrimary:
    """fetch_url_mcp must try httpx first."""

    @patch("src.recon.mcp.client.evaluate_recon_stage1_policy")
    @patch("src.recon.mcp.client.record_mcp_invocation")
    @patch("src.recon.mcp.client._fetch_via_httpx")
    def test_httpx_success_returns_directly(
        self, mock_httpx: MagicMock, _audit: MagicMock, mock_policy: MagicMock,
    ) -> None:
        mock_policy.return_value = MagicMock(allowed=True, policy_id="test", reason="ok")
        mock_httpx.return_value = {
            "status": 200,
            "headers": {},
            "body": "<html></html>",
            "content_type": "text/html",
            "exists": True,
            "notes": "",
        }
        from src.recon.mcp.client import fetch_url_mcp

        result = fetch_url_mcp("https://example.com")
        assert result["exists"] is True
        assert result["status"] == 200
        mock_httpx.assert_called_once()

    @patch("src.recon.mcp.client.evaluate_recon_stage1_policy")
    @patch("src.recon.mcp.client.record_mcp_invocation")
    @patch("src.recon.mcp.client._fetch_via_mcp_sync")
    @patch("src.recon.mcp.client._fetch_via_httpx")
    def test_fallback_to_mcp_on_httpx_failure(
        self,
        mock_httpx: MagicMock,
        mock_mcp: MagicMock,
        _audit: MagicMock,
        mock_policy: MagicMock,
    ) -> None:
        mock_policy.return_value = MagicMock(allowed=True, policy_id="test", reason="ok")
        mock_httpx.return_value = {
            "status": 0,
            "headers": {},
            "body": "",
            "content_type": "",
            "exists": False,
            "notes": "httpx_fetch_failed",
        }
        mock_mcp.return_value = {
            "status": 200,
            "headers": {},
            "body": "mcp content",
            "content_type": "text/html",
            "exists": True,
            "notes": "",
        }
        from src.recon.mcp.client import fetch_url_mcp

        result = fetch_url_mcp("https://example.com")
        assert result["exists"] is True
        mock_httpx.assert_called_once()
        mock_mcp.assert_called_once()

    @patch("src.recon.mcp.client.evaluate_recon_stage1_policy")
    @patch("src.recon.mcp.client.record_mcp_invocation")
    @patch("src.recon.mcp.client._fetch_via_httpx")
    def test_policy_denied_returns_denied(
        self, mock_httpx: MagicMock, _audit: MagicMock, mock_policy: MagicMock,
    ) -> None:
        mock_policy.return_value = MagicMock(allowed=False, policy_id="deny", reason="blocked")
        from src.recon.mcp.client import fetch_url_mcp

        result = fetch_url_mcp("https://example.com")
        assert result["exists"] is False
        assert "denied" in result.get("notes", "")
        mock_httpx.assert_not_called()
