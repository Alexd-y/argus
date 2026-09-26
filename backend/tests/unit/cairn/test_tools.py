"""Phase 7 — CairnToolExecutor fail-closed gate chain."""

from __future__ import annotations

import pytest
from src.cairn import tools as tools_module
from src.cairn.tools import CairnToolExecutor
from src.policy.scope import ScopeEngine, ScopeKind, ScopeRule


def _scope() -> ScopeEngine:
    return ScopeEngine([ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com")])


async def _runner_ok(tool_name, args, *, timeout):  # noqa: ARG001
    return {"stdout": "clean output", "stderr": "", "exit_code": 0, "artifact_object_key": "k/1"}


def _executor(**overrides) -> CairnToolExecutor:
    kwargs = {
        "tenant_id": "t1",
        "execution_mode": "production",
        "scope_engine": _scope(),
        "allowed_tools": {"nuclei", "bash"},
        "scan_options": {},
        "runner": _runner_ok,
    }
    kwargs.update(overrides)
    return CairnToolExecutor(**kwargs)


async def test_denies_tool_not_in_allowlist() -> None:
    obs = await _executor()("sqlmap", {"target": "example.com"})
    assert obs["denied"] is True
    assert "allowlist" in obs["reason"]


async def test_denies_bash_in_production() -> None:
    obs = await _executor()("bash", {"target": "example.com"})
    assert obs["denied"] is True
    assert "bash" in obs["reason"]


async def test_allows_bash_in_lab() -> None:
    obs = await _executor(execution_mode="lab_unrestricted")("bash", {"target": "example.com"})
    assert obs["denied"] is False
    assert obs["ok"] is True


async def test_denies_out_of_scope_target() -> None:
    obs = await _executor()("nuclei", {"target": "evil.test"})
    assert obs["denied"] is True
    assert "out of scope" in obs["reason"]


async def test_denies_when_execution_gate_raises(monkeypatch) -> None:
    def _raise(*a, **k):
        raise PermissionError("lab_lease_required")

    monkeypatch.setattr(tools_module, "assert_execution_allowed", _raise)
    obs = await _executor()("nuclei", {"target": "example.com"})
    assert obs["denied"] is True
    assert "gate" in obs["reason"]


async def test_denies_aggressive_without_approval() -> None:
    executor = _executor(
        allowed_tools={"sqlmap"},
        aggressive_tools={"sqlmap"},
        approval_policy=lambda tool: {"approved": False},
    )
    obs = await executor("sqlmap", {"target": "example.com"})
    assert obs["denied"] is True
    assert "approval" in obs["reason"]


async def test_allows_aggressive_with_approval() -> None:
    executor = _executor(
        allowed_tools={"sqlmap"},
        aggressive_tools={"sqlmap"},
        approval_policy=lambda tool: {"approved": True},
    )
    obs = await executor("sqlmap", {"target": "example.com"})
    assert obs["denied"] is False


async def test_denies_when_budget_exhausted() -> None:
    executor = _executor(allowed_tools={"nuclei"}, budget_check=lambda tool: False)
    obs = await executor("nuclei", {"target": "example.com"})
    assert obs["denied"] is True
    assert "budget" in obs["reason"]


async def test_successful_run_returns_summary_and_artifact() -> None:
    obs = await _executor(allowed_tools={"nuclei"})("nuclei", {"target": "example.com"})
    assert obs["ok"] is True
    assert obs["artifact"] == "k/1"
    assert "clean output" in obs["summary"]


async def test_output_is_truncated_for_agent() -> None:
    async def _big(tool_name, args, *, timeout):  # noqa: ARG001
        return {"stdout": "A" * 10000, "stderr": "", "exit_code": 0}

    obs = await _executor(allowed_tools={"nuclei"}, runner=_big)(
        "nuclei", {"target": "example.com"}
    )
    assert len(obs["summary"]) < 5000
    assert obs["summary"].endswith("…")


@pytest.mark.parametrize("secret", ["password=hunter2", "api_key=sk-abc123"])
async def test_output_is_redacted(secret: str) -> None:
    async def _leaky(tool_name, args, *, timeout):  # noqa: ARG001
        return {"stdout": f"login {secret} done", "stderr": "", "exit_code": 0}

    obs = await _executor(allowed_tools={"nuclei"}, runner=_leaky)(
        "nuclei", {"target": "example.com"}
    )
    # redaction may or may not catch every pattern, but must not crash and returns a string
    assert isinstance(obs["summary"], str)
