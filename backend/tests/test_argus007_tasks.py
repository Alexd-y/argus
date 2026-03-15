"""Tests for ARGUS-007 Celery tasks — scan_phase_task, tool_run_task.

All tests use mocks only. No real Redis/Celery broker in CI.
"""

import sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


class TestScanPhaseTask:
    """scan_phase_task — runs state machine."""

    def test_scan_phase_task_invokes_state_machine(self) -> None:
        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock()
        mock_session = MagicMock()
        mock_session.execute = AsyncMock(return_value=MagicMock())
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_factory = MagicMock(return_value=mock_cm)

        with (
            patch("src.tasks.create_task_engine_and_session", return_value=(mock_engine, mock_factory)),
            patch("src.tasks.run_scan_state_machine", new_callable=AsyncMock) as mock_sm,
        ):
            from src.tasks import scan_phase_task

            result = scan_phase_task(
                "scan-123",
                "00000000-0000-0000-0000-000000000001",
                "https://example.com",
                {},
            )

            mock_sm.assert_called_once()
            call_args = mock_sm.call_args
            assert call_args[0][1] == "scan-123"
            assert call_args[0][2] == "00000000-0000-0000-0000-000000000001"
            assert call_args[0][3] == "https://example.com"
            assert result["status"] == "completed"
            assert result["scan_id"] == "scan-123"


class TestToolRunTask:
    """tool_run_task — executes tool with guardrails."""

    def test_tool_run_task_validates_and_executes(self) -> None:
        with (
            patch("src.tasks.execute_command") as mock_exec,
            patch("src.tasks.validate_target_for_tool") as mock_validate,
        ):
            mock_validate.return_value = {"allowed": True, "reason": ""}
            mock_exec.return_value = {
                "success": True,
                "stdout": "ok",
                "stderr": "",
                "return_code": 0,
                "execution_time": 1.0,
            }

            from src.tasks import tool_run_task

            result = tool_run_task("nmap", "nmap -sV 8.8.8.8", target="8.8.8.8")

            mock_validate.assert_called_once_with("8.8.8.8", "nmap")
            mock_exec.assert_called_once()
            assert result["success"] is True
            assert result["tool"] == "nmap"

    def test_tool_run_task_blocks_private_ip(self) -> None:
        with (
            patch("src.tasks.execute_command") as mock_exec,
            patch("src.tasks.validate_target_for_tool") as mock_validate,
        ):
            mock_validate.return_value = {
                "allowed": False,
                "reason": "Private or loopback IP addresses are not allowed",
            }

            from src.tasks import tool_run_task

            result = tool_run_task("nmap", "nmap -sV 192.168.1.1", target="192.168.1.1")

            mock_exec.assert_not_called()
            assert result["success"] is False
            assert "private" in result["stderr"].lower() or "loopback" in result["stderr"].lower()

    def test_tool_run_task_no_target_skips_validation(self) -> None:
        """When target is None, validation is skipped."""
        with (
            patch("src.tasks.execute_command") as mock_exec,
            patch("src.tasks.validate_target_for_tool") as mock_validate,
        ):
            mock_exec.return_value = {
                "success": True,
                "stdout": "ok",
                "stderr": "",
                "return_code": 0,
                "execution_time": 0.1,
            }

            from src.tasks import tool_run_task

            result = tool_run_task("nmap", "nmap -sV 8.8.8.8", target=None)

            mock_validate.assert_not_called()
            mock_exec.assert_called_once()
            assert result["success"] is True

    def test_tool_run_task_use_sandbox_true_passed_to_executor(self) -> None:
        """use_sandbox=True is passed to execute_command."""
        with (
            patch("src.tasks.execute_command") as mock_exec,
            patch("src.tasks.validate_target_for_tool") as mock_validate,
        ):
            mock_validate.return_value = {"allowed": True, "reason": ""}
            mock_exec.return_value = {
                "success": True,
                "stdout": "ok",
                "stderr": "",
                "return_code": 0,
                "execution_time": 0.1,
            }

            from src.tasks import tool_run_task

            tool_run_task(
                "nmap",
                "nmap -sV 8.8.8.8",
                target="8.8.8.8",
                use_sandbox=True,
            )

            call_kwargs = mock_exec.call_args[1]
            assert call_kwargs["use_sandbox"] is True

    def test_tool_run_task_use_sandbox_false_passed_to_executor(self) -> None:
        """use_sandbox=False overrides settings."""
        with (
            patch("src.tasks.execute_command") as mock_exec,
            patch("src.tasks.validate_target_for_tool") as mock_validate,
        ):
            mock_validate.return_value = {"allowed": True, "reason": ""}
            mock_exec.return_value = {
                "success": True,
                "stdout": "ok",
                "stderr": "",
                "return_code": 0,
                "execution_time": 0.1,
            }

            from src.tasks import tool_run_task

            tool_run_task(
                "nmap",
                "nmap -sV 8.8.8.8",
                target="8.8.8.8",
                use_sandbox=False,
            )

            call_kwargs = mock_exec.call_args[1]
            assert call_kwargs["use_sandbox"] is False

    def test_scan_phase_task_on_exception_re_raises(self) -> None:
        """When state machine raises, exception propagates (no real broker)."""
        mock_engine = MagicMock()
        mock_engine.dispose = AsyncMock()
        mock_session = MagicMock()
        mock_session.execute = AsyncMock(return_value=MagicMock())
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_session)
        mock_cm.__aexit__ = AsyncMock(return_value=None)

        mock_err_session = MagicMock()
        mock_err_session.execute = AsyncMock(return_value=MagicMock())
        mock_err_session.commit = AsyncMock()
        mock_err_cm = MagicMock()
        mock_err_cm.__aenter__ = AsyncMock(return_value=mock_err_session)
        mock_err_cm.__aexit__ = AsyncMock(return_value=None)
        mock_factory = MagicMock(side_effect=[mock_cm, mock_err_cm])

        with (
            patch("src.tasks.create_task_engine_and_session", return_value=(mock_engine, mock_factory)),
            patch("src.tasks.run_scan_state_machine", new_callable=AsyncMock) as mock_sm,
        ):
            mock_sm.side_effect = RuntimeError("State machine error")

            from src.tasks import scan_phase_task

            with pytest.raises(RuntimeError, match="State machine error"):
                scan_phase_task(
                    "scan-123",
                    "00000000-0000-0000-0000-000000000001",
                    "https://example.com",
                    {},
                )
