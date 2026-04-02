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


class TestSandboxPython:
    """POST /api/v1/sandbox/python — disabled by default; policy when enabled."""

    def test_python_disabled_returns_501(self, client: TestClient) -> None:
        with patch.object(settings, "argus_sandbox_python_enabled", False):
            response = client.post(
                "/api/v1/sandbox/python",
                json={"code": "print(1)", "timeout_sec": 10},
            )
        assert response.status_code == 501
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
