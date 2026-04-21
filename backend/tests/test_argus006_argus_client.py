"""Tests for ARGUS-006 ArgusClient (MCP server HTTP client).

Unit tests with mocked httpx (ArgusClient uses httpx.Client, not requests).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx

BACKEND_DIR = Path(__file__).resolve().parent.parent
ARGUS_ROOT = BACKEND_DIR.parent
MCP_SERVER_DIR = ARGUS_ROOT / "mcp-server"
if str(MCP_SERVER_DIR) not in sys.path:
    sys.path.insert(0, str(MCP_SERVER_DIR))

from argus_mcp import ArgusClient  # noqa: E402


def _stub_init(*_args: object, **_kwargs: object) -> None:
    """No-op __init__ for tests that construct the client via __new__."""
    return None


class TestArgusClient:
    """ArgusClient — HTTP client for ARGUS backend API."""

    def test_init_connects_to_health_endpoint(self) -> None:
        """ArgusClient __init__ performs health check on server_url."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_client_instance = MagicMock()
        mock_client_instance.get.return_value = mock_response

        with patch("argus_mcp.httpx.Client", return_value=mock_client_instance):
            client = ArgusClient("http://127.0.0.1:8000", timeout=60)

        assert client.server_url == "http://127.0.0.1:8000"
        assert client.timeout == 60
        mock_client_instance.get.assert_called()
        path = mock_client_instance.get.call_args[0][0]
        assert path == "/api/v1/health"

    def test_create_scan_returns_json_on_success(self) -> None:
        """create_scan returns API response on success."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"scan_id":"scan-001"}'
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "scan_id": "scan-001",
            "status": "queued",
            "message": "Scan created",
        }

        with patch.object(ArgusClient, "__init__", _stub_init):
            client = ArgusClient.__new__(ArgusClient)
            client.server_url = "http://127.0.0.1:8000"
            client.timeout = 300
            client._headers = MagicMock(return_value={"Content-Type": "application/json"})
            client._client = MagicMock()
            client._client.post.return_value = mock_response

            result = client.create_scan("https://example.com", email="test@argus.local")

        assert result["scan_id"] == "scan-001"
        assert result["status"] == "queued"
        client._client.post.assert_called_once()
        call_args = client._client.post.call_args
        assert call_args[0][0] == "/api/v1/scans"
        body = call_args[1]["json"]
        assert body["target"] == "https://example.com"
        assert body["email"] == "test@argus.local"
        assert "options" in body
        assert "scan_mode" in body

    def test_get_scan_status_gets_correct_endpoint(self) -> None:
        """get_scan_status GETs /api/v1/scans/:id with correct URL."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b"{}"
        mock_response.headers = {"content-type": "application/json"}
        mock_response.json.return_value = {
            "id": "scan-001",
            "status": "running",
            "progress": 50,
            "phase": "scanning",
            "target": "https://example.com",
            "created_at": "2026-03-08T12:00:00Z",
        }

        with patch.object(ArgusClient, "__init__", _stub_init):
            client = ArgusClient.__new__(ArgusClient)
            client.server_url = "http://127.0.0.1:8000"
            client.timeout = 300
            client._headers = MagicMock(return_value={"Content-Type": "application/json"})
            client._client = MagicMock()
            client._client.get.return_value = mock_response

            result = client.get_scan_status("scan-001")

        assert result["id"] == "scan-001"
        assert result["status"] == "running"
        client._client.get.assert_called_once()
        assert client._client.get.call_args[0][0] == "/api/v1/scans/scan-001"
        assert client._client.get.call_args[1]["headers"] == {"Content-Type": "application/json"}

    def test_request_exception_returns_error_dict(self) -> None:
        """On httpx.RequestError, create_scan returns error dict with error key."""
        req = httpx.Request("POST", "http://127.0.0.1:8000/api/v1/scans")

        with patch.object(ArgusClient, "__init__", _stub_init):
            client = ArgusClient.__new__(ArgusClient)
            client.server_url = "http://127.0.0.1:8000"
            client.timeout = 300
            client._headers = MagicMock(return_value={"Content-Type": "application/json"})
            client._client = MagicMock()
            client._client.post.side_effect = httpx.ConnectError("Connection refused", request=req)

            result = client.create_scan("https://example.com")

        assert "error" in result
        assert "Connection" in result["error"] or "refused" in result["error"]
        assert result.get("status") == "error"
