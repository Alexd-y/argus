"""Recon-MCP provenance — ``run_kal_mcp_tool`` buffers ToolRun records.

Fix A wired ``execute_command`` into the per-scan ToolRun buffer, but recon
port/DNS/HTTP tools (naabu/nmap/…) run through the KAL-MCP executor, which was
never recorded — leaving ``tool_runs`` empty despite ``RECON_DEEP_PORT_SCAN``.
This verifies both execution paths (legacy + signed) now buffer provenance,
and that missing scan context is a no-op.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from src.core.config import settings
from src.recon.mcp import kal_executor as ke
from src.tools.executor import drain_pending_tool_runs


@pytest.fixture(autouse=True)
def _bypass_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate ToolRun buffering from policy / guardrails / MinIO details."""
    monkeypatch.setattr(
        ke,
        "evaluate_kal_mcp_policy",
        lambda **_k: SimpleNamespace(allowed=True, reason=None, policy_id="test"),
    )
    monkeypatch.setattr(ke, "validate_target_for_tool", lambda _h, _b: {"allowed": True})
    monkeypatch.setattr(ke, "_upload_kal_raw_streams", lambda *_a, **_k: [])


def _run(monkeypatch: pytest.MonkeyPatch, *, scan_id: str | None) -> dict[str, object]:
    return ke.run_kal_mcp_tool(
        category="recon",
        argv=["nmap", "-p", "80", "example.com"],
        target="http://example.com/",
        tenant_id="t1",
        scan_id=scan_id,
        password_audit_opt_in=False,
    )


def test_legacy_path_buffers_tool_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_recon_signed_runner", False)
    monkeypatch.setattr(
        ke,
        "run_argv_simple_sync",
        lambda *_a, **_k: {"success": True, "stdout": "scan-out", "stderr": "", "return_code": 0},
    )
    scan_id = "scan-kal-legacy-1"
    drain_pending_tool_runs(scan_id)  # ensure clean slate

    _run(monkeypatch, scan_id=scan_id)

    records = drain_pending_tool_runs(scan_id)
    assert len(records) == 1
    rec = records[0]
    assert rec["tool_name"] == "nmap"
    assert rec["status"] == "success"
    assert "nmap" in rec["input_params"]["command"]
    assert rec["output_raw"] == "scan-out"


def test_signed_path_buffers_tool_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_recon_signed_runner", True)

    async def _fake_signed(*_a: object, **_k: object) -> dict[str, object]:
        return {"stdout": "SIGNED-KAL", "stderr": "", "exit_code": 0, "duration_ms": 5}

    monkeypatch.setattr(ke, "run_signed_tool", _fake_signed)
    monkeypatch.setattr(
        ke,
        "run_argv_simple_sync",
        lambda *_a, **_k: (_ for _ in ()).throw(AssertionError("legacy must not run")),
    )
    scan_id = "scan-kal-signed-1"
    drain_pending_tool_runs(scan_id)

    out = _run(monkeypatch, scan_id=scan_id)
    assert out["stdout"] == "SIGNED-KAL"

    records = drain_pending_tool_runs(scan_id)
    assert len(records) == 1
    rec = records[0]
    assert rec["tool_name"] == "nmap"
    assert rec["status"] == "success"
    assert rec["output_raw"] == "SIGNED-KAL"


def test_failed_execution_buffers_error_status(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_recon_signed_runner", False)
    monkeypatch.setattr(
        ke,
        "run_argv_simple_sync",
        lambda *_a, **_k: {"success": False, "stdout": "", "stderr": "boom", "return_code": 1},
    )
    scan_id = "scan-kal-legacy-fail-1"
    drain_pending_tool_runs(scan_id)

    _run(monkeypatch, scan_id=scan_id)

    records = drain_pending_tool_runs(scan_id)
    assert len(records) == 1
    assert records[0]["status"] == "error"


def test_missing_scan_context_is_noop(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_recon_signed_runner", False)
    monkeypatch.setattr(
        ke,
        "run_argv_simple_sync",
        lambda *_a, **_k: {"success": True, "stdout": "out", "stderr": "", "return_code": 0},
    )
    _run(monkeypatch, scan_id=None)
    # No scan_id → nothing buffered under empty/None key.
    assert drain_pending_tool_runs("") == []
    assert drain_pending_tool_runs("None") == []
