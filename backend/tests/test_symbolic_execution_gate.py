"""P0-2 — symbolic execution honesty gate + LLM angr-script synthesis.

angr proves paths through a real binary; a web (URL) target can never be proven.
Verifies run_symbolic_execution skips non-binary/web inputs (no run, no false
``proven``) and synthesizes a target-specific angr script via the LLM for real
binaries.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from src.orchestration import symbolic_execution as se
from src.orchestration.symbolic_execution import (
    SymbolicExecutionRequest,
    _is_binary_target,
    run_symbolic_execution,
    synthesize_angr_script,
)


def test_is_binary_target_rejects_web_and_accepts_paths() -> None:
    assert _is_binary_target("https://app.example.com/login") is False
    assert _is_binary_target("http://10.0.0.1:8080") is False
    assert _is_binary_target("app.example.com") is False  # bare hostname
    assert _is_binary_target("") is False
    assert _is_binary_target("/tmp/fuzz_bin") is True
    assert _is_binary_target("C:\\build\\app.exe") is True
    assert _is_binary_target("fuzz_bin") is True  # plain local binary name


@pytest.mark.asyncio
async def test_honesty_gate_skips_web_target(monkeypatch) -> None:
    """A URL target must NOT run angr and must NOT be labelled proven."""
    ran = {"execute": False}

    def _fake_execute(*_a, **_k):
        ran["execute"] = True
        return {"success": True, "stdout": "VULNERABLE: path found\nInput: AAAA", "return_code": 0}

    monkeypatch.setattr("src.tools.executor.execute_command", _fake_execute, raising=False)

    result = await run_symbolic_execution(
        SymbolicExecutionRequest(
            binary_path="https://app.example.com/login",
            source_function="q",
            sink_function="xss",
        ),
        use_sandbox=False,
    )
    assert result.proven is False
    assert result.vulnerable is False
    assert "binary target" in result.error.lower()
    assert ran["execute"] is False  # angr never ran over a URL


@pytest.mark.asyncio
async def test_synthesize_prefers_llm_script(monkeypatch) -> None:
    async def _ok(*_a, **_k):
        return "```python\nimport angr\nproject = angr.Project('/tmp/app')\n```"

    monkeypatch.setattr("src.llm.facade.call_llm_unified", _ok, raising=False)
    script = await synthesize_angr_script(
        SymbolicExecutionRequest(binary_path="/tmp/app", source_function="main")
    )
    assert "import angr" in script
    assert "```" not in script


@pytest.mark.asyncio
async def test_synthesize_falls_back_to_stub(monkeypatch) -> None:
    async def _raise(*_a, **_k):
        raise RuntimeError("WRB offline")

    monkeypatch.setattr("src.llm.facade.call_llm_unified", _raise, raising=False)
    script = await synthesize_angr_script(
        SymbolicExecutionRequest(binary_path="/tmp/app", source_function="main", sink_function="sys")
    )
    assert "angr.Project('/tmp/app'" in script  # generic stub


@pytest.mark.asyncio
async def test_real_binary_runs_angr(monkeypatch) -> None:
    ran = {"execute": 0}

    async def _raise(*_a, **_k):
        raise RuntimeError("WRB offline")  # -> fallback stub

    def _fake_execute(*_a, **_k):
        ran["execute"] += 1
        return {"success": True, "stdout": "", "stderr": "", "return_code": 0}

    monkeypatch.setattr("src.llm.facade.call_llm_unified", _raise, raising=False)
    monkeypatch.setattr("src.tools.executor.execute_command", _fake_execute, raising=False)

    result = await run_symbolic_execution(
        SymbolicExecutionRequest(binary_path="/tmp/app_bin", source_function="main"),
        use_sandbox=False,
    )
    assert "binary target" not in result.error.lower()  # not gate-skipped
    assert ran["execute"] >= 1  # angr ran on the real binary path
    assert result.proven is False  # empty output => no false proof


@pytest.mark.asyncio
async def test_malicious_llm_script_rejected(monkeypatch) -> None:
    """LLM output touching os/subprocess is discarded for the trusted stub (not run)."""

    async def _evil(*_a, **_k):
        return "import os\nimport angr\nos.system('id')\nproject = angr.Project('/tmp/app')\n"

    monkeypatch.setattr("src.llm.facade.call_llm_unified", _evil, raising=False)
    script = await synthesize_angr_script(
        SymbolicExecutionRequest(binary_path="/tmp/app", source_function="main")
    )
    assert "os.system" not in script
    assert "import os" not in script
    assert "angr.Project('/tmp/app'" in script  # fell back to the deterministic stub


@pytest.mark.asyncio
async def test_llm_script_forces_sandbox(monkeypatch) -> None:
    """A validated LLM script must run with use_sandbox=True even when caller passed False."""
    seen: dict = {}

    async def _ok(*_a, **_k):
        return "import angr\nimport claripy\nproject = angr.Project('/tmp/app')\nprint('done')\n"

    def _fake_execute(command, use_sandbox=False, timeout_sec=0, **_k):  # noqa: ARG001
        seen["use_sandbox"] = use_sandbox
        return {"success": True, "stdout": "", "stderr": "", "return_code": 0}

    monkeypatch.setattr("src.llm.facade.call_llm_unified", _ok, raising=False)
    monkeypatch.setattr("src.tools.executor.execute_command", _fake_execute, raising=False)

    await run_symbolic_execution(
        SymbolicExecutionRequest(binary_path="/tmp/app", source_function="main"),
        use_sandbox=False,
    )
    assert seen.get("use_sandbox") is True


def test_module_exports_synthesize() -> None:
    assert "synthesize_angr_script" in se.__all__
