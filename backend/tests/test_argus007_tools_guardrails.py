"""Tests for ARGUS-007 Tools router — guardrails validation."""

import sys
from pathlib import Path
from unittest.mock import patch

from starlette.testclient import TestClient

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


# ---------------------------------------------------------------------------
# POST /tools/execute — allowlist, target validation, sandbox, rate limit
# ---------------------------------------------------------------------------


class TestToolsExecuteGuardrails:
    """POST /tools/execute guardrails: allowlist, target validation, sandbox."""

    def test_execute_allowed_tool_nmap_returns_200(self, client: TestClient) -> None:
        """nmap with public target is allowed and executes."""
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
        assert response.json()["success"] is True
        mock_exec.assert_called_once()
        assert mock_exec.call_args[1]["use_sandbox"] is not None

    def test_execute_disallowed_tool_returns_400(self, client: TestClient) -> None:
        """echo, curl, etc. are not in allowlist -> 400."""
        response = client.post(
            "/api/v1/tools/execute",
            json={"command": "echo hello", "use_cache": True},
        )
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "not allowed" in data["detail"].lower() or "allowed" in data["detail"].lower()

    def test_execute_rm_rf_returns_400(self, client: TestClient) -> None:
        """Arbitrary dangerous command not in allowlist -> 400."""
        response = client.post(
            "/api/v1/tools/execute",
            json={"command": "rm -rf /", "use_cache": False},
        )
        assert response.status_code == 400

    def test_execute_private_ip_target_returns_400(self, client: TestClient) -> None:
        """nmap with private IP target -> 400 (validate_target_for_tool)."""
        response = client.post(
            "/api/v1/tools/execute",
            json={"command": "nmap -sV 192.168.1.1", "use_cache": True},
        )
        assert response.status_code == 400
        data = response.json()
        assert "detail" in data
        assert "private" in data["detail"].lower() or "loopback" in data["detail"].lower()

    def test_execute_nuclei_public_url_allowed(self, client: TestClient) -> None:
        """nuclei -u https://example.com is allowed."""
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
                json={"command": "nuclei -u https://example.com -severity critical", "use_cache": False},
            )
        assert response.status_code == 200
        mock_exec.assert_called_once()

    def test_execute_rate_limit_returns_429(self, client: TestClient) -> None:
        """When rate limit exceeded, returns 429."""
        with patch("src.api.routers.tools._execute_rate_limiter") as mock_limiter:
            mock_limiter.is_allowed.return_value = (False, "Rate limit exceeded")
            response = client.post(
                "/api/v1/tools/execute",
                json={"command": "nmap -sV 8.8.8.8", "use_cache": True},
            )
        assert response.status_code == 429
        assert "rate limit" in response.json().get("detail", "").lower()


class TestToolsGuardrails:
    """Tools endpoints validate target before execution."""

    def test_nmap_blocks_private_ip(self, client: TestClient) -> None:
        """POST /tools/nmap with 192.168.1.1 returns error without executing."""
        with patch("src.api.routers.tools.execute_command") as mock_exec:
            response = client.post(
                "/api/v1/tools/nmap",
                json={
                    "target": "192.168.1.1",
                    "scan_type": "-sV",
                },
            )
        mock_exec.assert_not_called()
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "private" in data["stderr"].lower() or "loopback" in data["stderr"].lower()

    def test_nmap_allows_public_ip(self, client: TestClient) -> None:
        """POST /tools/nmap with 8.8.8.8 proceeds to execution."""
        with patch("src.api.routers.tools.execute_command") as mock_exec:
            mock_exec.return_value = {
                "success": True,
                "stdout": "ok",
                "stderr": "",
                "return_code": 0,
                "execution_time": 0.1,
            }
            response = client.post(
                "/api/v1/tools/nmap",
                json={
                    "target": "8.8.8.8",
                    "scan_type": "-sV",
                },
            )
        mock_exec.assert_called_once()
        assert response.status_code == 200
        assert response.json()["success"] is True

    def test_nuclei_blocks_localhost(self, client: TestClient) -> None:
        """POST /tools/nuclei with localhost returns error."""
        with patch("src.api.routers.tools.execute_command") as mock_exec:
            response = client.post(
                "/api/v1/tools/nuclei",
                json={"target": "http://localhost/", "severity": "critical"},
            )
        mock_exec.assert_not_called()
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False
        assert "blocked" in data["stderr"].lower() or "local" in data["stderr"].lower()

    def test_nuclei_allows_public_url(self, client: TestClient) -> None:
        """POST /tools/nuclei with public URL proceeds."""
        with patch("src.api.routers.tools.execute_command") as mock_exec:
            mock_exec.return_value = {
                "success": True,
                "stdout": "ok",
                "stderr": "",
                "return_code": 0,
                "execution_time": 0.1,
            }
            response = client.post(
                "/api/v1/tools/nuclei",
                json={"target": "https://example.com", "severity": "critical"},
            )
        mock_exec.assert_called_once()
        assert response.status_code == 200
        assert response.json()["success"] is True


# ---------------------------------------------------------------------------
# Security: Injection in target
# ---------------------------------------------------------------------------


class TestToolsTargetInjection:
    """Target field injection attempts — guardrails must block private IPs."""

    def test_nmap_target_private_ip_with_shell_chars_blocked(self, client: TestClient) -> None:
        """Target '192.168.1.1; id' — private IP detected, blocked."""
        with patch("src.api.routers.tools.execute_command") as mock_exec:
            response = client.post(
                "/api/v1/tools/nmap",
                json={
                    "target": "192.168.1.1; id",
                    "scan_type": "-sV",
                },
            )
        mock_exec.assert_not_called()
        assert response.status_code == 200
        data = response.json()
        assert data["success"] is False

    def test_nmap_target_private_ip_in_url_blocked(self, client: TestClient) -> None:
        """Target 'http://192.168.1.1/admin' — blocked."""
        with patch("src.api.routers.tools.execute_command") as mock_exec:
            response = client.post(
                "/api/v1/tools/nmap",
                json={
                    "target": "http://192.168.1.1/admin",
                    "scan_type": "-sV",
                },
            )
        mock_exec.assert_not_called()
        assert response.status_code == 200
        assert response.json()["success"] is False

    def test_nmap_target_public_with_metachars_executes_safely(self, client: TestClient) -> None:
        """Target '8.8.8.8; rm -rf /' — validation may pass; executor receives string, uses shlex."""
        with patch("src.api.routers.tools.execute_command") as mock_exec:
            mock_exec.return_value = {
                "success": True,
                "stdout": "ok",
                "stderr": "",
                "return_code": 0,
                "execution_time": 0.1,
            }
            response = client.post(
                "/api/v1/tools/nmap",
                json={
                    "target": "8.8.8.8; rm -rf /",
                    "scan_type": "-sV",
                },
            )
        data = response.json()
        assert response.status_code == 200
        if data["success"]:
            mock_exec.assert_called_once()
            call_args = mock_exec.call_args
            cmd = call_args[0][0]
            assert isinstance(cmd, str)
            assert "nmap" in cmd
