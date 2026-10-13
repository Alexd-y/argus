"""Wave 2a (etap 6) — the bounded tcpdump runner enforces the wall-clock cap.

The capture control flow is unit-tested with an injected fake process, so it
runs everywhere without a live tcpdump (which only exists in the sandbox image).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from src.evidence.pcap_capture import (
    CaptureSpec,
    CaptureUnavailable,
    pcap_session,
    run_tcpdump_capture,
)


class _FakeProc:
    """Minimal Popen stand-in recording terminate/kill and timing out on wait."""

    def __init__(self, *, time_out: bool, returncode: int = 0) -> None:
        self._time_out = time_out
        self.returncode = returncode
        self.terminated = False
        self.killed = False
        self.waits = 0
        self._exited = False

    def wait(self, timeout: float | None = None) -> int:
        self.waits += 1
        if self._time_out and self.waits == 1:
            raise subprocess.TimeoutExpired(cmd="tcpdump", timeout=timeout or 0)
        self._exited = True
        return self.returncode

    def poll(self) -> int | None:
        return self.returncode if self._exited else None

    def terminate(self) -> None:
        self.terminated = True

    def kill(self) -> None:  # pragma: no cover - only on a second timeout
        self.killed = True
        self._exited = True


def _spec() -> CaptureSpec:
    return CaptureSpec(target_host="10.0.0.5", ports=(80,), max_seconds=1)


def test_run_capture_enforces_wall_clock(tmp_path: Path) -> None:
    proc = _FakeProc(time_out=True)
    with patch("src.evidence.pcap_capture.tcpdump_available", return_value=True):
        result = run_tcpdump_capture(
            _spec(), output_path=tmp_path / "c.pcap", runner=lambda *a, **k: proc
        )
    # The wall-clock expired → tcpdump was stopped gracefully, reason recorded.
    assert result.stopped_reason == "wall_clock"
    assert proc.terminated is True


def test_run_capture_completes_within_budget(tmp_path: Path) -> None:
    proc = _FakeProc(time_out=False)
    with patch("src.evidence.pcap_capture.tcpdump_available", return_value=True):
        result = run_tcpdump_capture(
            _spec(), output_path=tmp_path / "c.pcap", runner=lambda *a, **k: proc
        )
    assert result.stopped_reason == "completed"
    assert proc.terminated is False


def test_run_capture_reports_error_on_failed_start(tmp_path: Path) -> None:
    # tcpdump exits fast with a non-zero code (bad interface / no CAP_NET_RAW):
    # this is NOT a clean "completed" capture — it must be surfaced as an error.
    proc = _FakeProc(time_out=False, returncode=1)
    with patch("src.evidence.pcap_capture.tcpdump_available", return_value=True):
        result = run_tcpdump_capture(
            _spec(), output_path=tmp_path / "c.pcap", runner=lambda *a, **k: proc
        )
    assert result.stopped_reason == "error"


def test_run_capture_unavailable_raises(tmp_path: Path) -> None:
    with (
        patch("src.evidence.pcap_capture.tcpdump_available", return_value=False),
        pytest.raises(CaptureUnavailable),
    ):
        run_tcpdump_capture(_spec(), output_path=tmp_path / "c.pcap")


def test_pcap_session_stops_on_exit(tmp_path: Path) -> None:
    proc = _FakeProc(time_out=False)
    with (
        patch("src.evidence.pcap_capture.tcpdump_available", return_value=True),
        pcap_session(
            _spec(), output_path=tmp_path / "c.pcap", runner=lambda *a, **k: proc
        ) as handle,
    ):
        assert handle is proc
    # Always stopped on exit, even on the clean path.
    assert proc.terminated is True
