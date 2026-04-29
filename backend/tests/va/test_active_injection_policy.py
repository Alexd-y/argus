"""VA / injection policy + quality gate (Phase 1 security-first)."""

from __future__ import annotations

import logging
from types import SimpleNamespace

import pytest

from src.core import config as core_config
from src.recon.mcp.policy import evaluate_tool_approval_policy
from src.reports.report_quality_gate import (
    build_report_quality_gate,
    evaluate_injection_finding_rules,
    normalize_findings_for_report,
)
from src.reports.valhalla_report_context import ValhallaReportContext


def test_destructive_tools_fail_closed_without_approval(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caplog.set_level(logging.INFO, logger="src.recon.mcp.policy")
    assert evaluate_tool_approval_policy("sqlmap", scan_approval_flags=None).reason == "requires_lab_mode"
    assert any(
        getattr(r, "event", None) == "destructive_requires_approval" for r in caplog.records
    )

    monkeypatch.setattr(core_config.settings, "argus_lab_mode", True, raising=False)
    monkeypatch.setattr(
        core_config.settings, "argus_destructive_lab_mode", True, raising=False
    )
    monkeypatch.setattr(
        core_config.settings, "argus_kill_switch_required", False, raising=False
    )
    assert evaluate_tool_approval_policy("sqlmap", scan_approval_flags={"sqlmap": True}).allowed is True


def test_quick_active_injection_mode_blocks_destructive_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        core_config.settings, "argus_active_injection_mode", "quick", raising=False
    )
    monkeypatch.setattr(core_config.settings, "argus_lab_mode", True, raising=False)
    monkeypatch.setattr(
        core_config.settings, "argus_destructive_lab_mode", True, raising=False
    )
    monkeypatch.setattr(
        core_config.settings, "argus_kill_switch_required", False, raising=False
    )
    d = evaluate_tool_approval_policy(
        "sqlmap", scan_approval_flags={"sqlmap": True}
    )
    assert d.allowed is False
    assert d.reason == "active_injection_quick_blocks_destructive"


def test_destructive_blocked_when_kill_switch_preflight_not_cleared(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(core_config.settings, "argus_lab_mode", True, raising=False)
    monkeypatch.setattr(
        core_config.settings, "argus_destructive_lab_mode", True, raising=False
    )
    monkeypatch.setattr(
        core_config.settings, "argus_kill_switch_required", True, raising=False
    )
    decision = evaluate_tool_approval_policy(
        "sqlmap", scan_approval_flags={"sqlmap": True}
    )
    assert decision.allowed is False
    assert decision.reason == "requires_kill_switch_clearance"


def test_injection_confirmed_downgraded_without_oast_or_xss_browser() -> None:
    xss = {
        "title": "Reflected XSS",
        "cwe": "CWE-79",
        "confidence": "confirmed",
        "injection_family": "xss",
        "evidence_refs": ["a1", "a2"],
        "proof_of_concept": {"payload": "<script>1</script>", "raw_response": "<html>x</html>"},
    }
    assert any("xss_confirmed_missing_browser_or_oast" in r for r in evaluate_injection_finding_rules(xss))
    out = normalize_findings_for_report([xss])
    assert str(out[0].get("confidence")) == "likely"

    ssrf = {
        "title": "SSRF",
        "cwe": "CWE-918",
        "confidence": "confirmed",
        "evidence_refs": ["e1"],
        "proof_of_concept": {"request_url": "http://x/?u=http://127.0.0.1"},
    }
    assert any("ssrf_confirmed_missing_oast" in r for r in evaluate_injection_finding_rules(ssrf))
    out2 = normalize_findings_for_report([ssrf])
    assert str(out2[0].get("confidence")) == "confirmed"


def test_quality_gate_injection_rules_trigger() -> None:
    bad = {
        "title": "Blind SQLi",
        "cwe": "CWE-89",
        "confidence": "confirmed",
        "evidence_refs": [],
        "proof_of_concept": {},
    }
    rules = evaluate_injection_finding_rules(bad)
    assert any("missing_evidence_refs" in r for r in rules)
    assert any("high_assertion_missing_poc_fields" in r for r in rules)

    scan = SimpleNamespace(
        options={
            "scan_approval_flags": {"sqlmap": False},
        }
    )
    cited = {
        "title": "SQL injection via search",
        "cwe": "CWE-89",
        "confidence": "likely",
        "evidence_refs": ["r1"],
        "proof_of_concept": {"tool": "sqlmap", "request_url": "https://t/?q=1"},
    }
    data = SimpleNamespace(
        valhalla_context=ValhallaReportContext(),
        findings=[cited],
        report=None,
        scan=scan,
    )
    gate = build_report_quality_gate(data)
    assert any("destructive_policy:tool_cited_without_scan_flag" in w for w in gate.warnings)
    assert any("destructive_policy" in g for g in gate.injection_finding_gates)
