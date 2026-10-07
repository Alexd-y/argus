"""P0-1 — fuzzing harness synthesis + honesty gate.

Verifies the fix for the no-op-stub gap: run_fuzzing_campaign must synthesize a
real target-specific harness via the LLM and MUST NOT run the fuzzer / emit crashes
when only a no-op stub harness is available (which would fabricate findings).
"""

from __future__ import annotations

import pytest
from src.orchestration import fuzzing
from src.orchestration.fuzzing import (
    FuzzingRequest,
    _is_stub_harness,
    generate_harness_stub,
    run_fuzzing_campaign,
    synthesize_harness,
)


def test_is_stub_harness_detects_noop_template() -> None:
    assert _is_stub_harness(generate_harness_stub("c")) is True
    assert _is_stub_harness(generate_harness_stub("c", "my_target")) is True
    assert _is_stub_harness("") is True
    assert _is_stub_harness("   ") is True
    real = (
        "#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){\n"
        "    parse_header(d, n); return 0;\n}\n"
    )
    assert _is_stub_harness(real) is False


@pytest.mark.asyncio
async def test_honesty_gate_skips_run_when_no_real_harness(monkeypatch) -> None:
    """LLM unavailable → stub harness → fuzzer must NOT run and NO crashes emitted."""

    async def _raise(*_a, **_k):
        raise RuntimeError("WRB offline")

    ran = {"execute": False}

    def _fake_execute(*_a, **_k):
        ran["execute"] = True
        return {"success": True, "stdout": "crash-1\nid:000,sig:11", "stderr": "", "return_code": 1}

    monkeypatch.setattr("src.llm.facade.call_llm_unified", _raise, raising=False)
    monkeypatch.setattr("src.tools.executor.execute_command", _fake_execute, raising=False)

    result = await run_fuzzing_campaign(
        FuzzingRequest(target_binary="app.c", language="c", engine="afl_plus_plus"),
        use_sandbox=False,
    )

    assert result.crashes == []  # no fabricated findings
    assert "skipped" in result.error.lower()
    assert ran["execute"] is False  # fuzzer never ran


@pytest.mark.asyncio
async def test_synthesize_harness_uses_llm_output(monkeypatch) -> None:
    real = (
        "```c\n#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){\n"
        "    decode(d, n); return 0;\n}\n```"
    )

    async def _ok(*_a, **_k):
        return real

    monkeypatch.setattr("src.llm.facade.call_llm_unified", _ok, raising=False)

    harness, is_stub = await synthesize_harness(
        FuzzingRequest(target_binary="decode", language="c", source_code="int decode(...){}")
    )
    assert is_stub is False
    assert "LLVMFuzzerTestOneInput" in harness
    assert "```" not in harness  # code fences stripped


@pytest.mark.asyncio
async def test_real_harness_runs_fuzzer(monkeypatch) -> None:
    """A provided real harness (non-compiled lang) proceeds to run the fuzzer."""
    ran = {"execute": 0}

    def _fake_execute(*_a, **_k):
        ran["execute"] += 1
        return {"success": True, "stdout": "", "stderr": "", "return_code": 0}

    monkeypatch.setattr("src.tools.executor.execute_command", _fake_execute, raising=False)

    real = (
        "import atheris\ndef TestOneInput(data):\n    pass\n"  # non-stub, language 'python'
    )
    result = await run_fuzzing_campaign(
        FuzzingRequest(
            target_binary="svc", language="python", engine="libfuzzer", harness_source=real
        ),
        use_sandbox=False,
    )
    assert "skipped" not in result.error.lower()
    assert ran["execute"] >= 1  # fuzzer ran (python is not compiled → no compile gate)


@pytest.mark.asyncio
async def test_llm_harness_forces_sandbox(monkeypatch) -> None:
    """An LLM-synthesized harness must compile/run with use_sandbox=True even when
    the caller passed use_sandbox=False (defense in depth)."""
    seen: list = []

    async def _ok(*_a, **_k):
        return (
            "#include <stdint.h>\nint LLVMFuzzerTestOneInput(const uint8_t *d, size_t n){\n"
            "    parse(d, n); return 0;\n}\n"
        )

    def _fake_execute(command, use_sandbox=False, timeout_sec=0, **_k):  # noqa: ARG001
        seen.append(use_sandbox)
        return {"success": True, "stdout": "", "stderr": "", "return_code": 0}

    monkeypatch.setattr("src.llm.facade.call_llm_unified", _ok, raising=False)
    monkeypatch.setattr("src.tools.executor.execute_command", _fake_execute, raising=False)

    await run_fuzzing_campaign(
        FuzzingRequest(target_binary="app", language="c", engine="libfuzzer"),
        use_sandbox=False,
    )
    assert seen and all(s is True for s in seen)  # compile + run both sandboxed


def test_module_exports_synthesize() -> None:
    assert "synthesize_harness" in fuzzing.__all__
