"""API tests for sandbox router (T03–T06): execute whitelist, python policy."""

from unittest.mock import patch

from starlette.testclient import TestClient

from src.core.config import settings


class TestSandboxExecute:
    """POST /api/v1/sandbox/execute — disallowed tool returns failure without running shell."""

    def test_execute_rejects_non_whitelisted_tool(self, client: TestClient) -> None:
        response = client.post(
            "/api/v1/sandbox/execute",
            json={"command": "rm -rf /", "use_sandbox": False},
        )
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is False
        assert body["return_code"] == 1
        assert "whitelist" in (body.get("stderr") or "").lower()

    def test_execute_includes_recovery_info_when_executor_returns_it(
        self, client: TestClient
    ) -> None:
        sample_recovery = {
            "original_tool": "curl",
            "final_tool": "curl",
            "recovery_used": False,
            "attempts": [
                {
                    "tool": "curl",
                    "exit_code": 0,
                    "error_type": "success",
                    "duration_sec": 0.02,
                },
            ],
            "total_attempts": 1,
            "is_stateful": False,
            "from_cache": False,
            "alternatives_available": ["httpx", "wget"],
        }
        mock_result = {
            "success": True,
            "stdout": "ok",
            "stderr": "",
            "return_code": 0,
            "execution_time": 0.05,
        }
        with patch(
            "src.api.routers.sandbox.execute_command_with_recovery",
            return_value=(mock_result, sample_recovery),
        ):
            response = client.post(
                "/api/v1/sandbox/execute",
                json={"command": "curl -s http://127.0.0.1", "use_sandbox": False},
            )
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is True
        assert body["recovery_info"] == sample_recovery


class TestSandboxPython:
    """POST /api/v1/sandbox/python — disabled by default; policy when enabled."""

    def test_python_disabled_returns_403(self, client: TestClient) -> None:
        with patch.object(settings, "argus_sandbox_python_enabled", False):
            response = client.post(
                "/api/v1/sandbox/python",
                json={"code": "print(1)", "timeout_sec": 10},
            )
        assert response.status_code == 403
        body = response.json()
        assert body.get("success") is False
        assert body.get("feature") == "sandbox_python"
        assert "detail" in body

    def test_python_rejects_eval(self, client: TestClient) -> None:
        with patch.object(settings, "argus_sandbox_python_enabled", True):
            response = client.post(
                "/api/v1/sandbox/python",
                json={"code": "eval('1+1')", "timeout_sec": 10},
            )
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is False
        assert "blocked" in (body.get("stderr") or "").lower()

    def test_python_rejects_subprocess_import(self, client: TestClient) -> None:
        with patch.object(settings, "argus_sandbox_python_enabled", True):
            response = client.post(
                "/api/v1/sandbox/python",
                json={"code": "import subprocess\nsubprocess.run(['echo','x'])", "timeout_sec": 10},
            )
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is False
        assert "blocked" in (body.get("stderr") or "").lower()

    def test_python_rejects_os_system(self, client: TestClient) -> None:
        with patch.object(settings, "argus_sandbox_python_enabled", True):
            response = client.post(
                "/api/v1/sandbox/python",
                json={"code": "import os\nos.system('echo pwned')", "timeout_sec": 10},
            )
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is False
        assert "blocked" in (body.get("stderr") or "").lower()

    def test_python_rejects_getattr(self, client: TestClient) -> None:
        with patch.object(settings, "argus_sandbox_python_enabled", True):
            response = client.post(
                "/api/v1/sandbox/python",
                json={"code": "getattr(__builtins__, 'exec')('1')", "timeout_sec": 10},
            )
        assert response.status_code == 200
        body = response.json()
        assert body["success"] is False
        assert "blocked" in (body.get("stderr") or "").lower()
