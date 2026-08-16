"""CONT-009 — legacy nuclei argv warnings and compiler routing."""

from __future__ import annotations

import shlex

from src.nuclei.legacy_inventory import NUCLEI_ARGV_CALL_SITES, get_call_site_status
from src.nuclei.legacy_metrics import get_legacy_argv_total, reset_legacy_argv_metrics
from src.recon.exploitation.adapters.nuclei_adapter import build_nuclei_exploit_argv
from src.recon.recon_http_probe import build_recon_nuclei_tech_argv
from src.schemas.exploitation.models import AttackPlan
from src.schemas.vulnerability_analysis.exploitation_candidates import (
    ExploitationCandidate,
    ExploitationDetailsXss,
)
from src.tasks.tools import run_nuclei_va_argv
from src.tools.executor import build_nuclei_command


def _nuclei_plan(command_config: dict) -> AttackPlan:
    candidate = ExploitationCandidate(
        target="https://example.com/",
        vulnerability_type="xss",
        confidence="high",
        evidence="test",
        exploitation_details=ExploitationDetailsXss(),
    )
    return AttackPlan(
        candidate_id="c1",
        candidate=candidate,
        selected_tool="nuclei",
        command_config=command_config,
        expected_outcome="verify template",
        risk_level="medium",
    )


def test_inventory_status_compiler_vs_legacy(monkeypatch):
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "0")
    assert get_call_site_status(
        "nuclei.profile_compiler.NucleiProfileCompiler.compile"
    ) == "compiler"
    assert get_call_site_status(
        "recon.vulnerability_analysis.active_scan.nuclei_va_adapter.build_nuclei_va_argv"
    ) == "legacy_warned"
    assert (
        get_call_site_status("tools.executor.build_nuclei_command") == "legacy_warned"
    )
    assert get_call_site_status("tasks.tools.run_nuclei_va_argv") == "legacy_warned"
    assert len(NUCLEI_ARGV_CALL_SITES) >= 5


def test_inventory_default_unset_is_compiler(monkeypatch):
    monkeypatch.delenv("ARGUS_NUCLEI_PROFILE_COMPILER", raising=False)
    for site in NUCLEI_ARGV_CALL_SITES:
        assert get_call_site_status(site) == "compiler"


def test_inventory_all_compiler_when_flag_on(monkeypatch):
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    for site in NUCLEI_ARGV_CALL_SITES:
        assert get_call_site_status(site) == "compiler"
    assert get_call_site_status("unknown.site") is None


def test_exploit_nuclei_legacy_increments_metric(monkeypatch):
    reset_legacy_argv_metrics()
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "0")
    plan = _nuclei_plan(
        {"target": "https://example.com/", "template_ids": ["xss"]},
    )
    before = get_legacy_argv_total()
    argv = build_nuclei_exploit_argv(plan)
    assert argv
    assert get_legacy_argv_total() == before + 1


def test_exploit_nuclei_compiler_skips_legacy_metric(monkeypatch):
    reset_legacy_argv_metrics()
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    plan = _nuclei_plan(
        {
            "target": "https://example.com/",
            "profile": "vuln_default",
            "mode": "production",
        },
    )
    before = get_legacy_argv_total()
    argv = build_nuclei_exploit_argv(plan)
    assert argv
    assert get_legacy_argv_total() == before


def test_recon_nuclei_compiler_path_when_flag_set(monkeypatch):
    reset_legacy_argv_metrics()
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    argv = build_recon_nuclei_tech_argv(
        "https://example.com/",
        rate_limit_rps=10,
        tags_csv="",
        templates_csv="",
    )
    assert argv[0] == "nuclei"
    assert "-tags" in argv
    assert argv[argv.index("-tags") + 1] == "tech"
    assert get_legacy_argv_total() == 0


def test_recon_nuclei_legacy_when_flag_off(monkeypatch):
    reset_legacy_argv_metrics()
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "0")
    before = get_legacy_argv_total()
    argv = build_recon_nuclei_tech_argv(
        "https://example.com/",
        rate_limit_rps=10,
        tags_csv="",
        templates_csv="",
    )
    assert argv[0] == "nuclei"
    assert get_legacy_argv_total() == before + 1


def test_executor_compiler_skips_legacy_metric(monkeypatch):
    reset_legacy_argv_metrics()
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    before = get_legacy_argv_total()
    cmd = build_nuclei_command("https://example.com/", "", "", "", "")
    argv = shlex.split(cmd)
    assert argv[0] == "nuclei"
    assert get_legacy_argv_total() == before


def test_executor_legacy_when_flag_off(monkeypatch):
    reset_legacy_argv_metrics()
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "0")
    before = get_legacy_argv_total()
    cmd = build_nuclei_command("https://example.com", "critical", "", "", "")
    argv = shlex.split(cmd)
    assert argv[0] == "nuclei"
    assert "-jsonl" not in argv
    assert get_legacy_argv_total() == before + 1


def test_run_nuclei_va_argv_compiler_from_scan_options(monkeypatch):
    reset_legacy_argv_metrics()
    monkeypatch.setenv("ARGUS_NUCLEI_PROFILE_COMPILER", "1")
    argv = run_nuclei_va_argv(
        "https://example.com/",
        scan_options={"execution_mode": "production", "nuclei_profile": "vuln_default"},
    )
    assert argv[0] == "nuclei"
    assert "-ni" in argv
    assert "-rate-limit" in argv
    assert get_legacy_argv_total() == 0
