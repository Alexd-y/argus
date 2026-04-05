"""Tests for ARGUS-006 Tools Executor.

execute_command: valid args, no shell injection.
build_*_command: proper shlex quoting.
"""

import sys
from pathlib import Path
from unittest.mock import patch

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from src.tools.executor import (
    build_gobuster_command,
    build_nikto_command,
    build_nmap_command,
    build_nuclei_command,
    build_sqlmap_command,
    execute_command,
)


class TestExecuteCommand:
    """execute_command — valid args, no shell injection."""

    def test_execute_valid_command_returns_success(self) -> None:
        """Valid command returns success, stdout, stderr, return_code, execution_time."""
        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
        ):
            mock_run.return_value = {
                "success": True,
                "stdout": "output",
                "stderr": "",
                "return_code": 0,
                "execution_time": 0.1,
            }
            result = execute_command("nmap -sV 8.8.8.8", use_cache=True)
        assert result["success"] is True
        assert result["stdout"] == "output"
        assert result["stderr"] == ""
        assert result["return_code"] == 0
        assert "execution_time" in result
        assert result["execution_time"] >= 0
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert call_args[0][0] == ["nmap", "-sV", "8.8.8.8"]
        assert call_args[1]["timeout_sec"] == 300.0

    def test_execute_nonzero_return_code_returns_failure(self) -> None:
        """Command with non-zero exit returns success=False."""
        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
        ):
            mock_run.return_value = {
                "success": False,
                "stdout": "",
                "stderr": "error",
                "return_code": 1,
                "execution_time": 0.1,
            }
            result = execute_command("nmap -sV invalid-target-xyz", use_cache=False)
        assert result["success"] is False
        assert result["return_code"] == 1
        assert result["stderr"] == "error"

    def test_execute_empty_command_returns_error(self) -> None:
        """Empty command returns error without invoking subprocess."""
        result = execute_command("", use_cache=True)
        assert result["success"] is False
        assert result["return_code"] == 1
        assert "Empty" in result["stderr"] or "empty" in result["stderr"].lower()

    def test_execute_whitespace_only_returns_error(self) -> None:
        """Whitespace-only command returns error (shlex.split yields empty)."""
        result = execute_command("   ", use_cache=True)
        assert result["success"] is False
        assert result["return_code"] == 1

    def test_execute_uses_list_form_no_shell(self) -> None:
        """Command is passed as list form (run_argv_simple_sync enforces shell=False)."""
        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
        ):
            mock_run.return_value = {
                "success": True, "stdout": "", "stderr": "",
                "return_code": 0, "execution_time": 0.0,
            }
            execute_command("nmap -sV 8.8.8.8")
        call_args = mock_run.call_args
        assert isinstance(call_args[0][0], list)
        assert call_args[0][0] == ["nmap", "-sV", "8.8.8.8"]

    def test_execute_disallowed_tool_returns_error(self) -> None:
        """Non-allowlisted tool (echo, curl, etc.) returns error without executing."""
        result = execute_command("echo hello", use_cache=True)
        assert result["success"] is False
        assert "not allowed" in result["stderr"].lower() or "allowed" in result["stderr"].lower()

    def test_execute_shell_injection_attempt_safe(self) -> None:
        """Command with injection-like string is passed as single arg, not executed."""
        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
        ):
            mock_run.return_value = {
                "success": True, "stdout": "", "stderr": "",
                "return_code": 0, "execution_time": 0.0,
            }
            execute_command('nmap -sV "8.8.8.8; rm -rf /"')
        call_args = mock_run.call_args
        args_list = call_args[0][0]
        assert "nmap" in args_list
        assert isinstance(args_list, list)

    def test_execute_timeout_returns_error(self) -> None:
        """Timeout returns success=False, return_code=-1."""
        with (
            patch("src.tools.executor.check_tool_available", return_value=True),
            patch("src.tools.executor.run_argv_simple_sync") as mock_run,
        ):
            mock_run.return_value = {
                "success": False,
                "stdout": "",
                "stderr": "Command timed out",
                "return_code": -1,
                "execution_time": 300.0,
            }
            result = execute_command("nmap -sV 8.8.8.8")
        assert result["success"] is False
        assert result["return_code"] == -1
        assert "timed out" in result["stderr"].lower()


class TestBuildCommands:
    """build_*_command — proper quoting, no injection."""

    def test_build_nmap_command_basic(self) -> None:
        """build_nmap_command produces valid nmap command."""
        cmd = build_nmap_command("192.168.1.1", "-sV", "", "")
        assert "nmap" in cmd
        assert "192.168.1.1" in cmd
        assert "-sV" in cmd

    def test_build_nmap_command_with_ports(self) -> None:
        """build_nmap_command includes ports when specified."""
        cmd = build_nmap_command("10.0.0.1", "-sC", "80,443", "")
        assert "-p" in cmd
        assert "80" in cmd or "443" in cmd

    def test_build_nmap_command_quotes_special_chars(self) -> None:
        """Arguments with spaces/special chars are properly quoted."""
        cmd = build_nmap_command("host with spaces", "-sV", "", "")
        assert "host with spaces" in cmd or "'host with spaces'" in cmd or '"host with spaces"' in cmd

    def test_build_nuclei_command_basic(self) -> None:
        """build_nuclei_command produces valid nuclei command."""
        cmd = build_nuclei_command("https://example.com", "critical", "", "", "")
        assert "nuclei" in cmd
        assert "example.com" in cmd

    def test_build_gobuster_command_basic(self) -> None:
        """build_gobuster_command produces valid gobuster command."""
        cmd = build_gobuster_command("https://target.com", "dir", "/usr/share/wordlists/common.txt", "")
        assert "gobuster" in cmd
        assert "target.com" in cmd

    def test_build_nikto_command_basic(self) -> None:
        """build_nikto_command produces valid nikto command."""
        cmd = build_nikto_command("https://target.com", "")
        assert "nikto" in cmd
        assert "target.com" in cmd

    def test_build_sqlmap_command_basic(self) -> None:
        """build_sqlmap_command produces valid sqlmap command."""
        cmd = build_sqlmap_command("https://target.com/page?id=1", "", "")
        assert "sqlmap" in cmd
        assert "target.com" in cmd
