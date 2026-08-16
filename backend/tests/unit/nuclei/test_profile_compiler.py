"""Golden tests for NucleiProfileCompiler (§9, Stage D)."""

from __future__ import annotations

import inspect

from src.execution_mode.mode import ExecutionMode
from src.nuclei.legacy_metrics import get_legacy_argv_total, reset_legacy_argv_metrics
from src.nuclei.profile_compiler import (
    NucleiProfileCompiler,
    default_profile_id_for_mode,
    load_scan_profile,
)
from src.recon.vulnerability_analysis.active_scan.nuclei_va_adapter import (
    build_nuclei_va_argv,
)

_TARGET = "https://example.com/page?x=1"


def test_production_vuln_default_includes_conservative_flags() -> None:
    argv = NucleiProfileCompiler.compile(
        "vuln_default",
        ExecutionMode.PRODUCTION,
        _TARGET,
    )
    assert argv[:3] == ["nuclei", "-u", _TARGET]
    assert "-ni" in argv
    assert "-rate-limit" in argv
    assert argv[argv.index("-rate-limit") + 1] == "12"


def test_lab_unrestricted_omits_conservative_flags() -> None:
    argv = NucleiProfileCompiler.compile(
        "lab_unrestricted",
        ExecutionMode.LAB_UNRESTRICTED,
        _TARGET,
    )
    assert "-ni" not in argv
    assert "-rate-limit" not in argv
    assert "-rl" not in argv
    assert "-c" not in argv
    assert "-disable-code" not in argv
    assert "-disable-javascript" not in argv


def test_lab_allows_code_and_headless_when_requested() -> None:
    argv = NucleiProfileCompiler.compile(
        "lab_unrestricted",
        ExecutionMode.LAB_UNRESTRICTED,
        _TARGET,
        allow_code=True,
        allow_headless=True,
        allow_javascript=True,
    )
    assert "-code" in argv
    assert "-headless" in argv
    assert "-enable-javascript" in argv


def test_single_compiler_used_by_va_adapter_when_profile_set() -> None:
    profile_argv = build_nuclei_va_argv(_TARGET, profile="vuln_default")
    compiler_argv = NucleiProfileCompiler.compile(
        "vuln_default",
        ExecutionMode.PRODUCTION,
        _TARGET,
    )
    assert profile_argv == compiler_argv


def test_va_adapter_default_argv_byte_compatible_without_profile(monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "0")
    legacy = build_nuclei_va_argv(_TARGET)
    assert legacy == [
        "nuclei",
        "-u",
        _TARGET,
        "-jsonl",
        "-duc",
        "-ni",
        "-rate-limit",
        "12",
        "-silent",
    ]


def test_va_adapter_flag_on_uses_compiler_without_legacy_metric(
    monkeypatch,
) -> None:
    reset_legacy_argv_metrics()
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    argv = build_nuclei_va_argv(_TARGET)
    compiler_argv = NucleiProfileCompiler.compile(
        "vuln_default",
        ExecutionMode.PRODUCTION,
        _TARGET,
    )
    assert argv == compiler_argv
    assert "-ni" in argv
    assert "-rate-limit" in argv
    assert get_legacy_argv_total() == 0


def test_va_adapter_lab_mode_selects_lab_profile(monkeypatch) -> None:
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    argv = build_nuclei_va_argv(_TARGET, mode="lab_unrestricted")
    lab_argv = NucleiProfileCompiler.compile(
        "lab_unrestricted",
        ExecutionMode.LAB_UNRESTRICTED,
        _TARGET,
    )
    assert argv == lab_argv
    assert "-ni" not in argv
    assert "-rate-limit" not in argv


def test_default_profile_id_for_mode() -> None:
    assert default_profile_id_for_mode("lab_unrestricted") == "lab_unrestricted"
    assert default_profile_id_for_mode(ExecutionMode.PRODUCTION) == "vuln_default"
    assert default_profile_id_for_mode(None) == "vuln_default"


def test_lab_profile_yaml_matches_spirit_of_section_9_6() -> None:
    profile = load_scan_profile("lab_unrestricted")
    assert profile.is_lab_unrestricted
    assert profile.require_verified_templates is False
    assert profile.disable_unsigned_templates is False
    assert profile.allow_remote_templates is True
    assert profile.allow_code is True
    assert profile.allow_headless is True
    assert profile.rate_limit_rps is None
    assert profile.concurrency is None
    assert profile.requires_approval is False


def test_profile_compiler_is_single_argv_builder() -> None:
    assert inspect.isclass(NucleiProfileCompiler)
    assert callable(NucleiProfileCompiler.compile)
