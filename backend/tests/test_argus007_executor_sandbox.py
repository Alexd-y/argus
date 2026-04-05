"""Tests for ARGUS-007 Executor sandbox integration."""

import sys
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from src.tools.executor import execute_command

_SUCCESS_RESULT = {
    "success": True,
    "stdout": "ok",
    "stderr": "",
    "return_code": 0,
    "execution_time": 0.1,
}


class TestExecutorSandbox:
    """execute_command with use_sandbox."""

    def test_use_sandbox_false_runs_locally(self) -> None:
        """When use_sandbox=False, runs subprocess directly (no docker)."""
        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
        ):
            mock_run.return_value = _SUCCESS_RESULT
            result = execute_command("nmap -sV 8.8.8.8", use_cache=True, use_sandbox=False)
        assert result["success"] is True
        call_args = mock_run.call_args
        assert call_args[0][0][0] == "nmap"
        assert "docker" not in str(call_args[0][0])

    def test_use_sandbox_true_when_enabled_prepends_docker_exec(self) -> None:
        """When use_sandbox=True and sandbox_enabled, runs via docker exec."""
        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
            patch("src.recon.sandbox_tool_runner.settings") as mock_strunner_settings,
            patch("src.tools.executor.settings") as mock_exec_settings,
        ):
            mock_strunner_settings.sandbox_enabled = True
            mock_strunner_settings.sandbox_container_name = "argus-sandbox"
            mock_exec_settings.recon_tools_timeout = 300
            mock_run.return_value = _SUCCESS_RESULT
            result = execute_command(
                "nmap -sV 8.8.8.8",
                use_cache=False,
                use_sandbox=True,
            )
        assert result["success"] is True
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert cmd[0] == "docker"
        assert cmd[1] == "exec"
        assert cmd[2] == "argus-sandbox"
        assert "nmap" in cmd
        assert "8.8.8.8" in cmd

    def test_use_sandbox_true_when_disabled_runs_locally(self) -> None:
        """When sandbox_enabled=False, use_sandbox=True is ignored."""
        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
            patch("src.recon.sandbox_tool_runner.settings") as mock_strunner_settings,
            patch("src.tools.executor.settings") as mock_exec_settings,
        ):
            mock_strunner_settings.sandbox_enabled = False
            mock_exec_settings.recon_tools_timeout = 300
            mock_run.return_value = _SUCCESS_RESULT
            result = execute_command("nmap -sV 8.8.8.8", use_sandbox=True)
        call_args = mock_run.call_args
        assert call_args[0][0][0] == "nmap"
        assert "docker" not in str(call_args[0][0])

    def test_use_sandbox_false_always_runs_locally_even_when_enabled(self) -> None:
        """use_sandbox=False bypasses docker even if sandbox_enabled=True."""
        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
        ):
            mock_run.return_value = _SUCCESS_RESULT
            result = execute_command("nmap -sV 8.8.8.8", use_cache=False, use_sandbox=False)
        assert result["success"] is True
        call_args = mock_run.call_args
        cmd = call_args[0][0]
        assert cmd[0] == "nmap"
        assert "docker" not in cmd

    def test_default_use_sandbox_false_runs_locally(self) -> None:
        """Default use_sandbox=False (no docker)."""
        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
        ):
            mock_run.return_value = _SUCCESS_RESULT
            result = execute_command("nmap -sV 8.8.8.8")
        call_args = mock_run.call_args
        assert call_args[0][0][0] == "nmap"
        assert "docker" not in str(call_args[0][0])
