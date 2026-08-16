"""QUICK-001 — NucleiProfileCompiler treats Quick as production, not LAB."""

from __future__ import annotations

import pytest
from src.execution_mode.mode import ExecutionMode
from src.nuclei.profile_compiler import NucleiProfileCompiler

_TARGET = "https://example.com/page?x=1"


def test_compile_lab_profile_with_quick_mode_raises() -> None:
    with pytest.raises(ValueError, match="lab_profile_requires_lab_unrestricted_mode"):
        NucleiProfileCompiler.compile(
            "lab_unrestricted",
            ExecutionMode.QUICK,
            _TARGET,
        )


def test_compile_fingerprint_safe_quick_uses_production_gates() -> None:
    argv = NucleiProfileCompiler.compile(
        "fingerprint_safe",
        ExecutionMode.QUICK,
        _TARGET,
    )
    assert "-ni" in argv
    assert "-rate-limit" in argv
    assert "-code" not in argv
