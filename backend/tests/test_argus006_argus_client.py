"""Tests for ARGUS-006 ArgusClient (MCP server HTTP client).

Unit tests with mocked requests.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_DIR = Path(__file__).resolve().parent.parent
ARGUS_ROOT = BACKEND_DIR.parent
MCP_SERVER_DIR = ARGUS_ROOT / "mcp-server"
if str(MCP_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(MCP_SERVER_DIR))

from argus_mcp import ArgusClient


class TestArgusClient:
    """ArgusClient — HTTP client for ARGUS backend API."""

    def test_init_connects_to_health_endpoint(self) -> None:
        """ArgusClient __init__ performs health check on server_url."""
        mock_session = MagicMock()
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.raise_for_status = MagicMock()
        mock_session.get.return_value = mock_get

        with patch("argus_mcp.requests.Session", return_value=mock_session):
            client = ArgusClient("http://127.0.0.1:8000", timeout=60)

        assert client.server_url == "http://127.0.0.1:8000"
        assert client.timeout == 60
        mock_session.get.assert_called()
        call_url = mock_session.get.call_args[0][0]
        assert "/api/v1/health" in call_url or "health" in call_url

    def test_create_scan_returns_json_on_success(self) -> None:
        """create_scan returns API response on success."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "scan_id": "scan-001",
            "status": "queued",
            "message": "Scan created",
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(ArgusClient, "__init__", lambda self, url, timeout=300: None):
            client = ArgusClient.__new__(ArgusClient)
            client.server_url = "http://127.0.0.1:8000"
            client.timeout = 300
            client._headers = MagicMock(return_value={"Content-Type": "application/json"})
            client.session = MagicMock()
            client.session.post.return_value = mock_response

            result = client.create_scan("https://example.com", email="test@argus.local")

        assert result["scan_id"] == "scan-001"
        assert result["status"] == "queued"
        client.session.post.assert_called_once()
        call_args = client.session.post.call_args
        assert call_args[0][0] == "http://127.0.0.1:8000/api/v1/scans"
        assert call_args[1]["json"] == {
            "target": "https://example.com",
            "email": "test@argus.local",
            "options": {},
        }
        assert call_args[1]["timeout"] == 300

    def test_get_scan_status_gets_correct_endpoint(self) -> None:
        """get_scan_status GETs /api/v1/scans/:id with correct URL."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "id": "scan-001",
            "status": "running",
            "progress": 50,
            "phase": "scanning",
            "target": "https://example.com",
            "created_at": "2026-03-08T12:00:00Z",
        }
        mock_response.raise_for_status = MagicMock()

        with patch.object(ArgusClient, "__init__", lambda self, url, timeout=300: None):
            client = ArgusClient.__new__(ArgusClient)
            client.server_url = "http://127.0.0.1:8000"
            client.timeout = 300
            client._headers = MagicMock(return_value={"Content-Type": "application/json"})
            client.session = MagicMock()
            client.session.get.return_value = mock_response

            result = client.get_scan_status("scan-001")

        assert result["id"] == "scan-001"
        assert result["status"] == "running"
        client.session.get.assert_called_once_with(
            "http://127.0.0.1:8000/api/v1/scans/scan-001",
            headers={"Content-Type": "application/json"},
            timeout=300,
        )

    def test_request_exception_returns_error_dict(self) -> None:
        """On RequestException, create_scan returns error dict with error key."""
        import requests

        with patch.object(ArgusClient, "__init__", lambda self, url, timeout=300: None):
            client = ArgusClient.__new__(ArgusClient)
            client.server_url = "http://127.0.0.1:8000"
            client.timeout = 300
            client._headers = MagicMock(return_value={"Content-Type": "application/json"})
            client.session = MagicMock()
            client.session.post.side_effect = requests.exceptions.ConnectionError("Connection refused")

            result = client.create_scan("https://example.com")

        assert "error" in result
        assert "Connection" in result["error"] or "refused" in result["error"]
        assert result.get("status") == "error"
