"""Single-control-plane routing for the shared recon exec (ARGUS_RECON_SIGNED_RUNNER)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from src.core.config import settings
from src.recon import sandbox_tool_runner as sr

_ARGV = ["nmap", "-p", "80", "example.com"]


def test_signed_runner_routes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_recon_signed_runner", True)

    async def _fake_signed(*_a: object, **_k: object) -> dict[str, object]:
        return {"stdout": "SIGNED", "stderr": "", "exit_code": 0, "duration_ms": 3}

    monkeypatch.setattr(sr, "run_signed_tool", _fake_signed)
    with patch("subprocess.run", side_effect=AssertionError("legacy must not run")):
        out = sr.run_argv_simple_sync(
            _ARGV, timeout_sec=30, tool_id="nmap", target="http://example.com/"
        )
    assert out["success"] is True
    assert out["stdout"] == "SIGNED"
    assert out["return_code"] == 0


def test_signed_none_falls_back_to_legacy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_recon_signed_runner", True)

    async def _fake_none(*_a: object, **_k: object) -> None:
        return None

    monkeypatch.setattr(sr, "run_signed_tool", _fake_none)
    completed = SimpleNamespace(returncode=0, stdout="legacy-out", stderr="")
    with patch("subprocess.run", return_value=completed):
        out = sr.run_argv_simple_sync(
            _ARGV, timeout_sec=30, tool_id="nmap", target="http://example.com/"
        )
    assert out["success"] is True
    assert out["stdout"] == "legacy-out"


def test_no_tool_id_uses_legacy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_recon_signed_runner", True)

    def _signed_tripwire(*_a: object, **_k: object) -> None:
        raise AssertionError("signed path needs a tool_id")

    monkeypatch.setattr(sr, "run_signed_tool", _signed_tripwire)
    completed = SimpleNamespace(returncode=0, stdout="legacy-out", stderr="")
    with patch("subprocess.run", return_value=completed):
        out = sr.run_argv_simple_sync(_ARGV, timeout_sec=30, tool_id=None, target="x")
    assert out["stdout"] == "legacy-out"


def test_flag_off_uses_legacy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "argus_recon_signed_runner", False)

    def _signed_tripwire(*_a: object, **_k: object) -> None:
        raise AssertionError("signed path must not run when flag off")

    monkeypatch.setattr(sr, "run_signed_tool", _signed_tripwire)
    completed = SimpleNamespace(returncode=0, stdout="legacy-out", stderr="")
    with patch("subprocess.run", return_value=completed):
        out = sr.run_argv_simple_sync(
            _ARGV, timeout_sec=30, tool_id="nmap", target="http://example.com/"
        )
    assert out["stdout"] == "legacy-out"
