"""KAL-MCP single-control-plane routing (ARGUS_RECON_SIGNED_RUNNER)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from src.core.config import settings
from src.recon.mcp import kal_executor as ke


@pytest.fixture(autouse=True)
def _bypass_gates(monkeypatch: pytest.MonkeyPatch) -> None:
    # Isolate the flag-routing logic from KAL policy / guardrails details.
    monkeypatch.setattr(
        ke,
        "evaluate_kal_mcp_policy",
        lambda **_k: SimpleNamespace(allowed=True, reason=None, policy_id="test"),
    )
    monkeypatch.setattr(ke, "validate_target_for_tool", lambda _h, _b: {"allowed": True})
    monkeypatch.setattr(ke, "_upload_kal_raw_streams", lambda *_a, **_k: [])


def test_signed_runner_routes_kal(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_recon_signed_runner", True)

    async def _fake_signed(*_a: object, **_k: object) -> dict[str, object]:
        return {"stdout": "SIGNED-KAL", "stderr": "", "exit_code": 0, "duration_ms": 5}

    monkeypatch.setattr(ke, "run_signed_tool", _fake_signed)

    def _legacy_tripwire(*_a: object, **_k: object) -> dict[str, object]:
        raise AssertionError("legacy run_argv_simple_sync must not run")

    monkeypatch.setattr(ke, "run_argv_simple_sync", _legacy_tripwire)

    out = ke.run_kal_mcp_tool(
        category="recon",
        argv=["nmap", "-p", "80", "example.com"],
        target="http://example.com/",
        tenant_id=None,
        scan_id=None,
        password_audit_opt_in=False,
    )
    assert out["stdout"] == "SIGNED-KAL"
    assert out["success"] is True
    assert out["return_code"] == 0
    assert out["policy_reason"] is None


def test_signed_runner_falls_back_to_legacy_when_none(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_recon_signed_runner", True)

    async def _fake_none(*_a: object, **_k: object) -> None:
        return None

    monkeypatch.setattr(ke, "run_signed_tool", _fake_none)
    monkeypatch.setattr(
        ke,
        "run_argv_simple_sync",
        lambda *_a, **_k: {"success": True, "stdout": "legacy-out", "stderr": "", "return_code": 0},
    )

    out = ke.run_kal_mcp_tool(
        category="recon",
        argv=["nmap", "-p", "80", "example.com"],
        target="http://example.com/",
        tenant_id=None,
        scan_id=None,
        password_audit_opt_in=False,
    )
    assert out["stdout"] == "legacy-out"
    assert out["success"] is True


def test_flag_off_uses_legacy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_recon_signed_runner", False)

    def _signed_tripwire(*_a: object, **_k: object) -> None:
        raise AssertionError("signed path must not run when flag off")

    monkeypatch.setattr(ke, "run_signed_tool", _signed_tripwire)
    monkeypatch.setattr(
        ke,
        "run_argv_simple_sync",
        lambda *_a, **_k: {"success": True, "stdout": "legacy-out", "stderr": "", "return_code": 0},
    )

    out = ke.run_kal_mcp_tool(
        category="recon",
        argv=["nmap", "-p", "80", "example.com"],
        target="http://example.com/",
        tenant_id=None,
        scan_id=None,
        password_audit_opt_in=False,
    )
    assert out["stdout"] == "legacy-out"
