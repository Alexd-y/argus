"""Unit tests for VA active-scan MCP runner (OWASP-002)."""

from __future__ import annotations

import asyncio
import io
import subprocess
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

from src.recon.vulnerability_analysis.active_scan.mcp_runner import (
    get_active_scan_semaphore,
    reset_active_scan_semaphore_for_testing,
    run_va_active_scan,
    run_va_active_scan_sync,
)


@pytest.fixture(autouse=True)
def _reset_sem() -> None:
    reset_active_scan_semaphore_for_testing()
    yield
    reset_active_scan_semaphore_for_testing()


def test_policy_denies_unknown_tool() -> None:
    r = run_va_active_scan_sync(
        tool_name="w3af",
        target="https://example.com/",
        argv=["echo", "x"],
        timeout_sec=5.0,
    )
    assert r["exit_code"] == -1
    assert r["tool_id"] == ""
    assert r["error_reason"] == "active_scan_tool_not_allowlisted"
    assert r["stdout"] == ""


def test_empty_argv() -> None:
    r = run_va_active_scan_sync(
        tool_name="ffuf",
        target="https://example.com/",
        argv=[],
        timeout_sec=5.0,
    )
    assert r["exit_code"] == -1
    assert r["tool_id"] == "ffuf"
    assert r["error_reason"] == "empty_argv"


def test_target_empty_host() -> None:
    r = run_va_active_scan_sync(
        tool_name="ffuf",
        target="https:///nohost",
        argv=[sys.executable, "-c", "print(1)"],
        timeout_sec=5.0,
    )
    assert r["exit_code"] == -1
    assert r["error_reason"] == "target_empty_or_no_host"


def test_target_localhost_rejected() -> None:
    r = run_va_active_scan_sync(
        tool_name="nuclei",
        target="http://localhost:8080/x",
        argv=[sys.executable, "-c", "print(1)"],
        timeout_sec=5.0,
    )
    assert r["exit_code"] == -1
    assert r["tool_id"] == "nuclei"
    assert r["error_reason"]


def test_sync_subprocess_success() -> None:
    r = run_va_active_scan_sync(
        tool_name="dalfox",
        target="https://example.com/",
        argv=[sys.executable, "-c", "print('ok')"],
        timeout_sec=10.0,
    )
    assert r["error_reason"] == ""
    assert r["exit_code"] == 0
    assert "ok" in r["stdout"]
    assert r["tool_id"] == "dalfox"


def test_popen_os_error() -> None:
    with patch("subprocess.Popen", side_effect=OSError(2, "no such file")):
        r = run_va_active_scan_sync(
            tool_name="gobuster",
            target="https://example.com/",
            argv=["/nonexistent/binary"],
            timeout_sec=5.0,
        )
    assert r["exit_code"] == -1
    assert r["error_reason"] == "exec_os_error"
    assert r["tool_id"] == "gobuster"


def test_timeout_mocked_process() -> None:
    class TimeoutProc:
        returncode: int | None = None

        def __init__(self) -> None:
            self.stdout = io.BytesIO(b"partial")
            self.stderr = io.BytesIO(b"")
            self._killed = False

        def wait(self, timeout: float | None = None) -> int | None:
            if self._killed:
                if self.returncode is None:
                    self.returncode = -9
                return self.returncode
            raise subprocess.TimeoutExpired(cmd="cmd", timeout=timeout)

        def kill(self) -> None:
            self._killed = True

    proc = TimeoutProc()
    with patch("subprocess.Popen", return_value=proc):
        r = run_va_active_scan_sync(
            tool_name="sqlmap",
            target="https://example.com/",
            argv=[sys.executable, "-c", "pass"],
            timeout_sec=0.01,
        )
    assert r["error_reason"] == "timeout"
    assert "partial" in r["stdout"]


@pytest.mark.asyncio
async def test_async_wraps_sync() -> None:
    with patch(
        "src.recon.vulnerability_analysis.active_scan.mcp_runner.run_va_active_scan_sync",
        return_value={
            "exit_code": 0,
            "stdout": "x",
            "stderr": "",
            "duration_ms": 1,
            "tool_id": "ffuf",
            "error_reason": "",
        },
    ) as m:
        r = await run_va_active_scan(
            tool_name="ffuf",
            target="https://example.com/",
            argv=[sys.executable, "-c", "print(1)"],
            timeout_sec=5.0,
            semaphore=asyncio.Semaphore(2),
        )
    assert r["stdout"] == "x"
    m.assert_called_once()


@pytest.mark.asyncio
async def test_get_active_scan_semaphore_singleton() -> None:
    a = await get_active_scan_semaphore()
    b = await get_active_scan_semaphore()
    assert a is b


@pytest.mark.asyncio
async def test_semaphore_limits_concurrency() -> None:
    sem = asyncio.Semaphore(1)
    t0 = time.perf_counter()

    async def once() -> None:
        await run_va_active_scan(
            tool_name="ffuf",
            target="https://example.com/",
            argv=[sys.executable, "-c", "import time; time.sleep(0.05)"],
            timeout_sec=30.0,
            semaphore=sem,
        )

    await asyncio.gather(once(), once())
    elapsed = time.perf_counter() - t0
    assert elapsed >= 0.08


def test_capture_truncates_via_max_bytes() -> None:
    big = b"x" * 100
    proc = MagicMock()
    proc.returncode = 0
    proc.stdout = io.BytesIO(big)
    proc.stderr = io.BytesIO(b"e")

    def fake_wait(timeout: float | None = None) -> int | None:
        return 0

    proc.wait = fake_wait
    proc.kill = MagicMock()

    with patch("subprocess.Popen", return_value=proc):
        r = run_va_active_scan_sync(
            tool_name="nuclei",
            target="https://example.com/",
            argv=[sys.executable, "-c", "pass"],
            timeout_sec=5.0,
            max_capture_bytes=20,
        )
    assert len(r["stdout"]) <= 20
    assert len(r["stderr"]) <= 20
