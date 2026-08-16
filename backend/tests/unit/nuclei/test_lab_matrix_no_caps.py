"""CONT-003 — LAB nuclei matrix: no -ni / rate / concurrency caps."""

from __future__ import annotations

import shlex

from src.nuclei.legacy_inventory import NUCLEI_ARGV_CALL_SITES, get_call_site_status
from src.nuclei.legacy_metrics import (
    get_legacy_argv_total,
    increment_legacy_argv,
    reset_legacy_argv_metrics,
)
from src.nuclei.profile_compiler import NucleiProfileCompiler
from src.recon.vulnerability_analysis.active_scan.nuclei_va_adapter import (
    build_nuclei_va_argv,
)
from src.tasks.tools import run_nuclei_va_argv
from src.tools.executor import build_nuclei_command


def test_inventory_lists_known_call_sites():
    assert len(NUCLEI_ARGV_CALL_SITES) >= 5
    assert any("nuclei_va_adapter" in s for s in NUCLEI_ARGV_CALL_SITES)


def test_lab_unrestricted_omits_conservative_flags():
    argv = NucleiProfileCompiler.compile(
        "lab_unrestricted",
        "lab_unrestricted",
        "https://app.lab.argus/",
        allow_code=True,
        allow_headless=True,
    )
    assert argv
    assert "-ni" not in argv
    assert "-rate-limit" not in argv
    assert "-c" not in argv  # concurrency short flag typically
    joined = " ".join(argv)
    assert "rate-limit" not in joined
    assert "bulk-size" not in joined


def test_production_vuln_default_keeps_caps():
    argv = NucleiProfileCompiler.compile(
        "vuln_default",
        "production",
        "https://example.com/",
    )
    assert argv
    assert "-ni" in argv
    assert "-rate-limit" in argv


def test_lab_adapter_omits_caps_when_mode_passed(monkeypatch):
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    argv = build_nuclei_va_argv(
        "https://app.lab.argus/",
        mode="lab_unrestricted",
    )
    assert argv
    assert "-ni" not in argv
    assert "-rate-limit" not in argv
    assert "-c" not in argv


def test_lab_executor_omits_caps(monkeypatch):
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    cmd = build_nuclei_command(
        "https://app.lab.argus/",
        "",
        "",
        "",
        "",
        execution_mode="lab_unrestricted",
    )
    argv = shlex.split(cmd)
    assert argv[0] == "nuclei"
    assert "-ni" not in argv
    assert "-rate-limit" not in argv
    assert "-c" not in argv


def test_lab_run_nuclei_va_argv_from_scan_options(monkeypatch):
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    argv = run_nuclei_va_argv(
        "https://app.lab.argus/",
        scan_options={"execution_mode": "lab_unrestricted"},
    )
    assert "-ni" not in argv
    assert "-rate-limit" not in argv
    joined = " ".join(argv)
    assert "rate-limit" not in joined


def test_inventory_compiler_when_flag_on(monkeypatch):
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    for site in NUCLEI_ARGV_CALL_SITES:
        assert get_call_site_status(site) == "compiler"


def test_legacy_metric_increments_only_on_fallback(monkeypatch):
    reset_legacy_argv_metrics()
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "0")
    before = get_legacy_argv_total()
    build_nuclei_va_argv("https://example.com/")
    assert get_legacy_argv_total() == before + 1

    reset_legacy_argv_metrics()
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    before = get_legacy_argv_total()
    build_nuclei_va_argv(
        "https://example.com/",
        profile="vuln_default",
        mode="production",
    )
    assert get_legacy_argv_total() == before
    build_nuclei_command("https://example.com/", "", "", "", "")
    run_nuclei_va_argv("https://example.com/", execution_mode="production")
    assert get_legacy_argv_total() == before


def test_increment_legacy_helper():
    reset_legacy_argv_metrics()
    n = increment_legacy_argv(caller="unit.test")
    assert n == 1
    assert get_legacy_argv_total() == 1
