"""Reliable ToolRun persistence — buffer + phase-boundary flush.

Replaces the dropped ``loop.create_task`` fire-and-forget: records are buffered
per scan and flushed synchronously into the phase transaction, so ``tool_runs``
is never silently empty.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from src.tools import executor
from src.tools.executor import (
    _schedule_tool_run_record,
    drain_pending_tool_runs,
    flush_tool_runs,
)


class _FakeSession:
    """Minimal stand-in that records ``add``ed ORM instances (no DB)."""

    def __init__(self) -> None:
        self.added: list[Any] = []

    def add(self, obj: Any) -> None:
        self.added.append(obj)


def _result(success: bool = True, stdout: str = "out") -> dict[str, Any]:
    return {"success": success, "stdout": stdout}


def _now() -> datetime:
    return datetime.now(UTC)


def _clear(scan_id: str) -> None:
    drain_pending_tool_runs(scan_id)


def test_missing_scan_context_does_not_buffer():
    _schedule_tool_run_record(None, None, "nmap", _result(), _now(), _now(), "nmap -sV t")
    _schedule_tool_run_record("t1", None, "nmap", _result(), _now(), _now(), "nmap -sV t")
    assert drain_pending_tool_runs("") == []


def test_buffer_and_drain_roundtrip():
    scan_id = "scan-drain-1"
    _clear(scan_id)
    _schedule_tool_run_record(
        "t1", scan_id, "nmap", _result(True, "scan output"), _now(), _now(), "nmap -sV t"
    )
    records = drain_pending_tool_runs(scan_id)
    assert len(records) == 1
    assert records[0]["tool_name"] == "nmap"
    assert records[0]["status"] == "success"
    assert records[0]["input_params"] == {"command": "nmap -sV t"}
    # Drain is destructive → second drain is empty.
    assert drain_pending_tool_runs(scan_id) == []


async def test_flush_persists_buffered_records_to_session():
    scan_id = "scan-flush-1"
    _clear(scan_id)
    _schedule_tool_run_record("t1", scan_id, "nmap", _result(True), _now(), _now(), "nmap t")
    _schedule_tool_run_record(
        "t1", scan_id, "nuclei", _result(False), _now(), _now(), "nuclei -u t"
    )
    session = _FakeSession()
    flushed = await flush_tool_runs(session, "t1", scan_id)
    assert flushed == 2
    assert len(session.added) == 2
    names = {r.tool_name for r in session.added}
    assert names == {"nmap", "nuclei"}
    statuses = {r.status for r in session.added}
    assert statuses == {"success", "error"}
    # Buffer drained by flush → re-flush is a no-op.
    assert await flush_tool_runs(session, "t1", scan_id) == 0


async def test_output_truncated_to_cap():
    scan_id = "scan-trunc-1"
    _clear(scan_id)
    big = "x" * (executor._TOOL_RUN_OUTPUT_MAX_CHARS + 500)
    _schedule_tool_run_record("t1", scan_id, "nmap", _result(True, big), _now(), _now(), "nmap t")
    records = drain_pending_tool_runs(scan_id)
    assert len(records[0]["output_raw"]) == executor._TOOL_RUN_OUTPUT_MAX_CHARS


async def test_flush_empty_returns_zero():
    assert await flush_tool_runs(_FakeSession(), "t1", "scan-empty-xyz") == 0
