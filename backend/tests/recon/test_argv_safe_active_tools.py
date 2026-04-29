"""P2-004 — argv list execution, no shell=True, out-of-scope skip (mocked subprocess)."""

from __future__ import annotations

import io
import sys
from collections.abc import Callable
from unittest.mock import MagicMock, patch

import pytest

from src.core import config as core_config
from src.recon.vulnerability_analysis.active_scan.dalfox_adapter import build_dalfox_argv
from src.recon.vulnerability_analysis.active_scan.mcp_runner import run_va_active_scan_sync
from src.recon.vulnerability_analysis.active_scan.nuclei_va_adapter import build_nuclei_va_argv
from src.recon.vulnerability_analysis.active_scan.sqlmap_va_adapter import build_sqlmap_va_argv


def _fake_proc() -> MagicMock:
    proc = MagicMock()
    proc.returncode = 0
    proc.stdout = io.BytesIO(b"")
    proc.stderr = io.BytesIO(b"")

    def _wait(timeout: float | None = None) -> int | None:
        return 0

    proc.wait = _wait
    proc.kill = MagicMock()
    return proc


@pytest.mark.parametrize(
    "tool_name,argv_builder",
    [
        ("dalfox", lambda: build_dalfox_argv("https://example.com/path?x=1")),
        ("sqlmap", lambda: build_sqlmap_va_argv("https://example.com/path?x=1", None)),
        ("nuclei", lambda: build_nuclei_va_argv("https://example.com/path?x=1")),
    ],
)
def test_popen_receives_argv_list_shell_false(
    tool_name: str,
    argv_builder: Callable[[], list[str]],
) -> None:
    argv = argv_builder()
    assert isinstance(argv, list)
    assert argv
    with patch("subprocess.Popen") as popen:
        popen.return_value = _fake_proc()
        run_va_active_scan_sync(
            tool_name=tool_name,
            target="https://example.com/",
            argv=argv,
            timeout_sec=5.0,
        )
    popen.assert_called_once()
    kwargs = popen.call_args.kwargs
    assert kwargs.get("shell") is False
    pos = popen.call_args[0]
    assert isinstance(pos[0], list)


def test_out_of_scope_skips_subprocess() -> None:
    with patch("subprocess.Popen") as popen, patch(
        "src.recon.vulnerability_analysis.active_scan.mcp_runner.validate_target_for_tool",
        return_value={"allowed": False, "reason": "target_out_of_engagement_scope"},
    ):
        r = run_va_active_scan_sync(
            tool_name="dalfox",
            target="https://example.com/",
            argv=build_dalfox_argv("https://example.com/"),
            timeout_sec=5.0,
        )
    popen.assert_not_called()
    assert r["exit_code"] == -1
    assert r["error_reason"] == "target_out_of_engagement_scope"


def test_default_timeout_uses_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core_config.settings, "argus_active_injection_timeout_sec", 99.0, raising=False)
    proc = _fake_proc()
    waits: list[float | None] = []

    def wait_capture(timeout: float | None = None) -> int | None:
        waits.append(timeout)
        return 0

    proc.wait = wait_capture
    with patch("subprocess.Popen", return_value=proc):
        run_va_active_scan_sync(
            tool_name="dalfox",
            target="https://example.com/",
            argv=[sys.executable, "-c", "print(1)"],
            timeout_sec=None,
        )
    assert waits == [99.0]
