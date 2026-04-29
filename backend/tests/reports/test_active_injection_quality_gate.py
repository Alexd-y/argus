"""Active injection policy + report quality gate (Phase 1)."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.core import config as core_config
from src.recon.mcp.policy import evaluate_tool_approval_policy
from src.reports.report_quality_gate import (
    build_active_injection_coverage,
    build_report_quality_gate,
    evaluate_injection_finding_rules,
    has_oast_callback_signal,
    has_xss_browser_or_oast_signal,
    map_injection_family,
)
from src.reports.valhalla_report_context import ValhallaReportContext, build_valhalla_report_context


def test_destructive_tools_fail_closed_without_approval(
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caplog.set_level(logging.INFO, logger="src.recon.mcp.policy")
    d = evaluate_tool_approval_policy("sqlmap", scan_approval_flags=None)
    assert d.allowed is False
    assert d.reason == "requires_lab_mode"
    assert any(getattr(r, "event", None) == "destructive_requires_approval" for r in caplog.records)
    d2 = evaluate_tool_approval_policy("commix", scan_approval_flags=None)
    assert d2.allowed is False
    assert d2.reason == "requires_lab_mode"

    ok = evaluate_tool_approval_policy("sqlmap", scan_approval_flags={"sqlmap": True})
    assert ok.allowed is False
    assert ok.reason == "requires_lab_mode"

    monkeypatch.setattr(core_config.settings, "argus_lab_mode", True, raising=False)
    monkeypatch.setattr(
        core_config.settings, "argus_destructive_lab_mode", True, raising=False
    )
    monkeypatch.setattr(
        core_config.settings, "argus_kill_switch_required", False, raising=False
    )
    ok2 = evaluate_tool_approval_policy("sqlmap", scan_approval_flags={"sqlmap": True})
    assert ok2.allowed is True

    safe = evaluate_tool_approval_policy("nuclei", scan_approval_flags=None)
    assert safe.allowed is True


def test_destructive_never_allowed_when_flags_none_even_with_lab_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(core_config.settings, "argus_lab_mode", True)
    monkeypatch.setattr(core_config.settings, "argus_destructive_lab_mode", True)
    monkeypatch.setattr(core_config.settings, "va_lab_profile_allow_destructive_tools", True)
    d = evaluate_tool_approval_policy("sqlmap", scan_approval_flags=None)
    assert d.allowed is False
    assert d.reason == "requires_approval"


def test_lab_profile_does_not_bypass_empty_approval_map(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core_config.settings, "argus_lab_mode", True)
    monkeypatch.setattr(core_config.settings, "argus_destructive_lab_mode", True)
    monkeypatch.setattr(core_config.settings, "va_lab_profile_allow_destructive_tools", True)
    d = evaluate_tool_approval_policy("sqlmap", scan_approval_flags={})
    assert d.allowed is False


def test_xss_poc_browser_validation_satisfies_gate() -> None:
    f = {
        "title": "Reflected XSS",
        "cwe": "CWE-79",
        "confidence": "confirmed",
        "evidence_refs": ["a1"],
        "proof_of_concept": {"browser_validation": True, "payload": "<img onerror=alert(1)>"},
    }
    assert has_xss_browser_or_oast_signal(f) is True
    assert not any("xss_confirmed_missing_browser_or_oast" in r for r in evaluate_injection_finding_rules(f))


def test_validated_status_triggers_strong_evidence_warning() -> None:
    f = {
        "title": "SSRF",
        "cwe": "CWE-918",
        "confidence": "likely",
        "validation_status": "validated",
        "evidence_quality": "moderate",
        "evidence_refs": ["e1", "e2"],
        "proof_of_concept": {"request_url": "http://x/?u=http://127.0.0.1"},
    }
    rules = evaluate_injection_finding_rules(f)
    assert any("confirmed_without_strong_evidence" in r for r in rules)


def test_xss_reflection_not_confirmed_without_browser_execution() -> None:
    f = {
        "title": "Reflected XSS in q",
        "description": "reflected content",
        "cwe": "CWE-79",
        "confidence": "confirmed",
        "injection_family": "xss",
        "evidence_refs": ["art-1"],
        "proof_of_concept": {
            "payload": "<script>alert(1)</script>",
            "raw_response": "<html>injection</html>",
        },
    }
    assert has_xss_browser_or_oast_signal(f) is False
    rules = evaluate_injection_finding_rules(f)
    assert any("xss_confirmed_missing_browser_or_oast" in r for r in rules)


def test_ssrf_confirmed_requires_oast_callback() -> None:
    f = {
        "title": "SSRF to internal service",
        "description": "server-side request forgery",
        "cwe": "CWE-918",
        "confidence": "confirmed",
        "evidence_refs": ["e1"],
        "proof_of_concept": {"request_url": "http://target/fetch?u=http://169.254.169.254/"},
    }
    assert map_injection_family(f) == "ssrf"
    assert has_oast_callback_signal(f) is False
    rules = evaluate_injection_finding_rules(f)
    assert any("ssrf_confirmed_missing_oast" in r for r in rules)

    f_ok = {**f, "description": "interactsh callback received: oast.proof"}
    assert has_oast_callback_signal(f_ok) is True
    assert not any("ssrf_confirmed_missing_oast" in r for r in evaluate_injection_finding_rules(f_ok))


def test_quality_gate_includes_active_injection_coverage() -> None:
    f = {
        "title": "Blind SQL injection",
        "cwe": "CWE-89",
        "confidence": "likely",
        "evidence_refs": ["r1"],
    }
    scan = SimpleNamespace(options={"active_injection_coverage": {"families": {"xss": {"status": "not_assessed", "reason": "scanner_skipped"}}}})
    data = SimpleNamespace(
        valhalla_context=ValhallaReportContext(),
        findings=[f],
        report=None,
        scan=scan,
    )
    gate = build_report_quality_gate(data)
    fam = gate.active_injection_coverage.get("families") or {}
    assert fam.get("xss", {}).get("status") == "not_assessed"
    assert fam.get("sqli", {}).get("status") == "assessed"


def test_quality_gate_blocks_confirmed_without_strong_evidence() -> None:
    f = {
        "title": "Blind SQL injection",
        "cwe": "CWE-89",
        "confidence": "confirmed",
        "evidence_refs": ["only-one-ref"],
        "proof_of_concept": {"request_url": "https://x/?id=1"},
    }
    from src.reports.report_quality_gate import score_evidence_quality

    assert score_evidence_quality(f) != "strong"
    rules = evaluate_injection_finding_rules(f)
    assert any("confirmed_without_strong_evidence" in r for r in rules)

    data = SimpleNamespace(
        valhalla_context=ValhallaReportContext(),
        findings=[f],
        report=None,
        scan=None,
    )
    gate = build_report_quality_gate(data)
    assert any("confirmed_without_strong_evidence" in w for w in gate.injection_evidence_warnings)


def test_payload_catalog_loaded() -> None:
    here = Path(__file__).resolve()
    catalog = here.parents[2] / "config" / "payloads" / "payload_catalog_index.json"
    if not catalog.is_file():
        pytest.skip("payload_catalog_index.json not present in this checkout")
    raw = json.loads(catalog.read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    assert "version" in raw


def test_valhalla_includes_active_injection_coverage_placeholder() -> None:
    ctx = build_valhalla_report_context(
        tenant_id="t",
        scan_id="s",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[],
        phase_inputs=[],
        findings=[{"title": "SQLi", "cwe": "CWE-89", "description": "injection"}],
        report_technologies=None,
        fetch_raw_bodies=False,
        scan_options={"active_injection_coverage": {"families": {"rce": {"status": "not_assessed", "reason": "not_in_scope"}}}},
    )
    c = ctx.active_injection_coverage
    rows = c.get("table_rows") or []
    assert any(r.get("family") == "sqli" and int(r.get("findings_count") or 0) >= 1 for r in rows)
    assert any(r.get("family") == "rce" and r.get("assessed") == "no" for r in rows)
    assert "sqli" in (c.get("injection_families_observed") or [])
    assert c.get("families", {}).get("sqli", {}).get("status") == "assessed"
    assert c.get("families", {}).get("rce", {}).get("status") == "not_assessed"


def test_valhalla_reads_active_injection_coverage_from_vuln_phase_output() -> None:
    ctx = build_valhalla_report_context(
        tenant_id="t",
        scan_id="s",
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=[
            (
                "vuln_analysis",
                {
                    "findings": [],
                    "active_injection_coverage": {
                        "families": {
                            "xss": {"status": "partial", "reason": "planned_but_execution_status_not_observed"},
                        },
                        "table_rows": [
                            {
                                "family": "xss",
                                "assessed": "partial",
                                "tool": "dalfox",
                                "status": "partial",
                                "not_assessed_reason": "planned_but_execution_status_not_observed",
                            }
                        ],
                    },
                },
            )
        ],
        phase_inputs=[],
        findings=[],
        report_technologies=None,
        fetch_raw_bodies=False,
        scan_options=None,
    )
    c = ctx.active_injection_coverage
    assert c["families"]["xss"]["status"] == "partial"
    row = next(r for r in c["table_rows"] if r["family"] == "xss")
    assert row["assessed"] == "partial"


def test_build_active_injection_coverage_empty_default() -> None:
    cov = build_active_injection_coverage([], None)
    assert cov.get("families") == {}
    assert cov.get("not_assessed_reasons") == {}
    assert cov.get("toolsHealth") == {}
    assert cov.get("table_rows") == []


def test_oast_callback_poc_flag_satisfies_ssrf_gate() -> None:
    f = {
        "title": "SSRF",
        "cwe": "CWE-918",
        "confidence": "confirmed",
        "evidence_refs": ["e1"],
        "proof_of_concept": {"request_url": "http://x/", "oast_callback": True},
    }
    assert has_oast_callback_signal(f) is True
    assert not any("ssrf_confirmed_missing_oast" in r for r in evaluate_injection_finding_rules(f))


def test_time_based_sqli_confirmed_requires_timing_samples() -> None:
    f = {
        "title": "Time-based blind SQL injection",
        "cwe": "CWE-89",
        "confidence": "confirmed",
        "evidence_refs": ["a", "b"],
        "proof_of_concept": {
            "request_method": "GET",
            "parameter": "id",
            "request": "GET /?id=1 HTTP/1.1",
            "type": "time-based blind",
        },
    }
    rules = evaluate_injection_finding_rules(f)
    assert any("sqli_time_based_missing_repeated_samples" in r for r in rules)
    f_ok = {
        **f,
        "proof_of_concept": {
            **f["proof_of_concept"],
            "timing_samples": [1.1, 1.2],
        },
    }
    assert not any("sqli_time_based_missing_repeated_samples" in r for r in evaluate_injection_finding_rules(f_ok))


def test_build_active_injection_coverage_stub_overlay_from_options() -> None:
    cov = build_active_injection_coverage(
        [],
        {
            "active_injection_coverage": {
                "not_assessed_reasons": {"ssrf": "no_interactsh"},
                "toolsHealth": {"sqlmap": "skipped"},
            }
        },
    )
    assert cov.get("not_assessed_reasons") == {"ssrf": "no_interactsh"}
    assert cov.get("toolsHealth") == {"sqlmap": "skipped"}
