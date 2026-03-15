"""Tests for ARGUS-006 Tools Router.

POST /api/v1/tools/nmap, /execute return 200.
"""

import sys
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from starlette.testclient import TestClient


class TestToolsExecute:
    """POST /api/v1/tools/execute."""

    def test_post_execute_returns_200_with_allowed_tool(self, client: TestClient) -> None:
        """POST /tools/execute with allowed tool (nmap) returns 200 and result structure."""
        with patch("src.api.routers.tools.execute_command") as mock_exec:
            mock_exec.return_value = {
                "success": True,
                "stdout": "ok",
                "stderr": "",
                "return_code": 0,
                "execution_time": 0.1,
            }
            response = client.post(
                "/api/v1/tools/execute",
                json={"command": "nmap -sV 8.8.8.8", "use_cache": True},
            )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert data["stdout"] == "ok"
        assert data["return_code"] == 0
        assert "execution_time" in data
        mock_exec.assert_called_once()
        call_args = mock_exec.call_args
        assert call_args[0][0] == "nmap -sV 8.8.8.8"
        assert "use_sandbox" in call_args[1]

    def test_post_execute_missing_command_returns_422(self, client: TestClient) -> None:
        """POST /tools/execute without command returns 422."""
        response = client.post(
            "/api/v1/tools/execute",
            json={"use_cache": True},
        )
        assert response.status_code == 422

    def test_post_execute_empty_command_returns_422(self, client: TestClient) -> None:
        """POST /tools/execute with empty command returns 422 (min_length=1)."""
        response = client.post(
            "/api/v1/tools/execute",
            json={"command": "", "use_cache": True},
        )
        assert response.status_code == 422


class TestToolsNmap:
    """POST /api/v1/tools/nmap."""

    def test_post_nmap_returns_200(self, client: TestClient) -> None:
        """POST /tools/nmap returns 200 and result structure (public target)."""
        with patch("src.api.routers.tools.execute_command") as mock_exec:
            mock_exec.return_value = {
                "success": True,
                "stdout": "nmap output",
                "stderr": "",
                "return_code": 0,
                "execution_time": 1.5,
            }
            response = client.post(
                "/api/v1/tools/nmap",
                json={
                    "target": "8.8.8.8",
                    "scan_type": "-sV",
                    "ports": "80,443",
                    "additional_args": "-T4",
                },
            )
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is True
        assert "stdout" in data
        assert "return_code" in data
        mock_exec.assert_called_once()
        call_cmd = mock_exec.call_args[0][0]
        assert "nmap" in call_cmd
        assert "8.8.8.8" in call_cmd
        assert "-sV" in call_cmd

    def test_post_nmap_minimal_payload_returns_200(self, client: TestClient) -> None:
        """POST /tools/nmap with minimal payload (target only) returns 200."""
        with patch("src.api.routers.tools.execute_command") as mock_exec:
            mock_exec.return_value = {
                "success": False,
                "stdout": "",
                "stderr": "nmap not found",
                "return_code": 127,
                "execution_time": 0.0,
            }
            response = client.post(
                "/api/v1/tools/nmap",
                json={"target": "1.1.1.1"},
            )
        assert response.status_code == 200
        data = response.json()
        assert "success" in data
        assert "return_code" in data

    def test_post_nmap_missing_target_returns_422(self, client: TestClient) -> None:
        """POST /tools/nmap without target returns 422."""
        response = client.post(
            "/api/v1/tools/nmap",
            json={"scan_type": "-sV"},
        )
        assert response.status_code == 422
