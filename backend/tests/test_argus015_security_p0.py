"""ARGUS-015: Security hardening P0 — headers, exception handling, executor, path traversal."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


class TestSecurityHeaders:
    """Security headers middleware adds OWASP-recommended headers."""

    REQUIRED_HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    }

    @pytest.fixture
    def client(self):
        from main import app
        from starlette.testclient import TestClient
        return TestClient(app)

    def test_security_headers_present_on_response(self, client) -> None:
        """All responses include X-Content-Type-Options, X-Frame-Options, etc."""
        resp = client.get("/api/v1/health")
        assert resp.status_code == 200
        for name, expected in self.REQUIRED_HEADERS.items():
            assert resp.headers.get(name) == expected, f"Missing or wrong {name}"

    def test_security_headers_on_api_endpoint(self, client) -> None:
        """Headers present on API routes."""
        resp = client.get("/")
        assert resp.status_code == 200
        assert resp.headers.get("X-Content-Type-Options") == "nosniff"

    def test_security_headers_present_on_all_responses(self, client) -> None:
        """Security headers present on 200 and 404 responses."""
        for path, expected_status in [("/api/v1/health", 200), ("/nonexistent", 404)]:
            resp = client.get(path)
            assert resp.status_code == expected_status
            for name in self.REQUIRED_HEADERS:
                assert name in resp.headers, f"Missing {name} on {path}"


class TestExceptionHandlerNoTraceback:
    """Unhandled exceptions return generic message, never stack trace."""

    def test_unhandled_exception_returns_generic_message(self) -> None:
        """500 responses use generic message, no stack trace in body."""
        from fastapi import FastAPI
        from src.core.exception_handlers import (
            GENERIC_ERROR_MESSAGE,
            register_exception_handlers,
        )
        from starlette.testclient import TestClient

        app = FastAPI()

        @app.get("/raise")
        def _raise():
            raise RuntimeError("Internal secret detail")

        register_exception_handlers(app)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/raise")
        assert resp.status_code == 500
        body = resp.json()
        assert "detail" in body
        assert body["detail"] == GENERIC_ERROR_MESSAGE
        assert "Internal secret" not in body.get("detail", "")
        assert "RuntimeError" not in body.get("detail", "")
        assert "traceback" not in resp.text.lower()

    def test_exception_handler_returns_no_traceback_patterns(self) -> None:
        """Response body contains no traceback, file paths, or line numbers."""
        from fastapi import FastAPI
        from src.core.exception_handlers import register_exception_handlers
        from starlette.testclient import TestClient

        app = FastAPI()

        @app.get("/raise")
        def _raise():
            raise ValueError("sensitive path: /etc/passwd")

        register_exception_handlers(app)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/raise")
        assert resp.status_code == 500
        text = resp.text.lower()
        assert "traceback" not in text
        assert "most recent call" not in text
        assert "/etc/passwd" not in resp.text
        assert "valueerror" not in text


class TestExecutorNoLeak:
    """Executor never leaks internal error details to API response."""

    def test_exception_returns_generic_stderr(self) -> None:
        """On Exception, stderr is generic, not str(exception)."""
        from src.tools.executor import execute_command

        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
        ):
            mock_run.side_effect = FileNotFoundError("nmap not found in PATH")
            result = execute_command("nmap -sV 8.8.8.8")
        assert result["success"] is False
        assert result["stderr"] == "Command execution failed"
        assert "FileNotFoundError" not in result["stderr"]
        assert "PATH" not in result["stderr"]

    def test_timeout_expired_returns_generic_stderr(self) -> None:
        """On TimeoutExpired, stderr is generic, no internal details."""
        from src.tools.executor import execute_command

        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
        ):
            mock_run.side_effect = RuntimeError("Command timed out after 300s")
            result = execute_command("nmap -sV 8.8.8.8")
        assert result["success"] is False
        assert result["stderr"] == "Command execution failed"
        assert "300" not in result["stderr"]

    def test_executor_stderr_sanitized_on_any_exception(self) -> None:
        """Any exception during execution returns generic stderr, never raw message."""
        from src.tools.executor import execute_command

        for exc in [
            PermissionError("Permission denied: /usr/bin/nmap"),
            OSError(2, "No such file or directory", "/opt/tools/nmap"),
        ]:
            with (
                patch("src.tools.executor.check_tool_available", return_value=True),
                patch("src.tools.executor.run_argv_simple_sync") as mock_run,
            ):
                mock_run.side_effect = exc
                result = execute_command("nmap -sV 8.8.8.8")
            assert result["success"] is False
            assert result["stderr"] == "Command execution failed"
            assert "/usr" not in result["stderr"]
            assert "/opt" not in result["stderr"]
            assert "Permission" not in result["stderr"]
            assert "No such file" not in result["stderr"]

    def test_run_argv_receives_list_not_string(self) -> None:
        """run_argv_simple_sync receives a list of args (no shell injection)."""
        from src.tools.executor import execute_command

        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
        ):
            mock_run.return_value = {"success": True, "stdout": "", "stderr": "", "return_code": 0}
            execute_command("nmap -sV 8.8.8.8")
        args = mock_run.call_args[0][0]
        assert isinstance(args, list)


class TestPathTraversalStorage:
    """Storage path components validated against path traversal."""

    def test_sanitize_rejects_path_traversal(self) -> None:
        """Path components with .. or slashes raise ValueError."""
        from src.storage.s3 import build_object_key

        with pytest.raises(ValueError, match="path traversal"):
            build_object_key("tenant", "scan", "report", "../../etc/passwd")

        with pytest.raises(ValueError, match="path traversal"):
            build_object_key("tenant", "scan", "report", "file/../etc")

        with pytest.raises(ValueError, match="path traversal"):
            build_object_key("tenant", "scan", "report", "file\\..\\etc")

    def test_sanitize_accepts_valid_path(self) -> None:
        """Valid UUID-like components pass."""
        from src.storage.s3 import build_object_key

        key = build_object_key(
            "00000000-0000-0000-0000-000000000001",
            "abc123",
            "report",
            "report.pdf",
        )
        assert key == "00000000-0000-0000-0000-000000000001/abc123/report/report.pdf"
