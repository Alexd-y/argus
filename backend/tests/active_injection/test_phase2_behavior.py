"""P2-010 — Phase 2 active injection / evidence / coverage behavior (unit-level).

AI payload execution guarantees are covered by ``tests/test_ai_payload_candidates_phase2.py``
(``test_ai_generated_payloads_are_not_executed_directly``) — not duplicated here.

Overlap with ``tests/reports/test_active_injection_quality_gate.py`` is avoided for
``test_quality_gate_blocks_confirmed_without_strong_evidence`` by asserting the aggregate
path here instead of duplicating the full gate fixture.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.core.config import Settings, lab_destructive_execution_allowed
from src.core import config as core_config
from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle
from src.recon.mcp.policy import evaluate_tool_approval_policy
from src.recon.vulnerability_analysis.active_scan.commix_va_adapter import build_commix_va_argv
from src.recon.vulnerability_analysis.active_scan.injection_findings_normalize import (
    DEFAULT_INJECTION_EVIDENCE_RULES,
    normalize_evidence_quality_for_family,
)
from src.recon.vulnerability_analysis.active_scan.injection_planner import (
    ActiveInjectionPlannerFlags,
    _nominal_families_for_mode,
    build_active_injection_coverage_from_plan,
    build_injection_plan,
    build_injection_plan_from_settings,
)
from src.recon.vulnerability_analysis.active_scan.input_surface_inventory import (
    InputSurfaceInventory,
    InputSurfaceItem,
    build_input_surface_inventory,
)
from src.recon.vulnerability_analysis.active_scan.sqlmap_va_adapter import build_sqlmap_va_argv
from src.recon.vulnerability_analysis.active_scan.va_active_scan_phase import (
    _lab_destructive_execution_allowed_for_scan,
    _target_url_matches_scan_lab_allowlist,
    run_va_active_scan_phase,
)
from src.reports.report_quality_gate import (
    aggregate_injection_evidence_violations,
    build_active_injection_coverage,
    build_report_quality_gate,
    evaluate_injection_finding_rules,
    has_oast_callback_signal,
    has_xss_browser_or_oast_signal,
)
from src.reports.valhalla_report_context import ValhallaReportContext


def _flags(
    *,
    lab: bool = False,
    oast: bool = False,
    destructive: frozenset[str] | None = None,
) -> ActiveInjectionPlannerFlags:
    return ActiveInjectionPlannerFlags(
        lab_destructive_execution_allowed=lab,
        oast_enabled=oast,
        destructive_tool_ids=destructive or frozenset({"sqlmap", "commix", "dalfox", "xsstrike"}),
    )


def _inventory_multi_surface() -> InputSurfaceInventory:
    """One URL per location flavor used by planner tests."""
    return InputSurfaceInventory(
        items=[
            InputSurfaceItem(
                surface_id="q1",
                url="https://app.example/api/search",
                method="GET",
                param_name="q",
                location="query",
                source="t",
                evidence_ref="e-q",
            ),
            InputSurfaceItem(
                surface_id="f1",
                url="https://app.example/login",
                method="POST",
                param_name="password",
                location="form",
                source="t",
                evidence_ref="e-f",
            ),
            InputSurfaceItem(
                surface_id="j1",
                url="https://app.example/api/v2/order",
                method="POST",
                param_name="$.items[0].sku",
                location="json",
                source="t",
                evidence_ref="e-j",
            ),
            InputSurfaceItem(
                surface_id="g1",
                url="https://app.example/graphql",
                method="POST",
                param_name="token",
                location="graphql",
                source="t",
                evidence_ref="e-g",
            ),
            InputSurfaceItem(
                surface_id="h1",
                url="https://app.example/secure",
                method="GET",
                param_name="Authorization",
                location="header",
                source="t",
                evidence_ref="e-h",
            ),
        ]
    )


def test_input_surface_inventory_from_query_forms_json_openapi_graphql() -> None:
    """Merge params (query + OpenAPI-style path), forms, JSON OpenAPI body paths, GraphQL vars."""
    recon: dict = {
        "params_inventory": [
            {
                "full_url": "https://api.example/v1/users/42?debug=0",
                "param_name": "debug",
                "method": "GET",
                "location": "query",
            },
            {
                "full_url": "https://api.example/v1/users/{id}",
                "param_name": "id",
                "method": "GET",
                "location": "path",
            },
        ],
        "forms_inventory": [
            {
                "form_action": "https://api.example/v1/session",
                "method": "POST",
                "field_name": "username",
                "content_type": "application/x-www-form-urlencoded",
            }
        ],
        "endpoint_inventory": [
            {
                "url": "https://api.example/v1/checkout",
                "method": "POST",
                "content_type": "application/json",
                "json_fields": ["paymentMethodId", "shipping.address.zip"],
            }
        ],
        "graphql": {
            "endpoint": "https://api.example/graphql",
            "variables": ["orderId", "filter"],
        },
    }
    inv = build_input_surface_inventory(recon)
    by_key = {(it.location, it.param_name, it.url) for it in inv.items}
    assert ("query", "debug", "https://api.example/v1/users/42?debug=0") in by_key
    assert ("path", "id", "https://api.example/v1/users/{id}") in by_key
    assert ("form", "username", "https://api.example/v1/session") in by_key
    assert ("json", "paymentMethodId", "https://api.example/v1/checkout") in by_key
    assert ("json", "shipping.address.zip", "https://api.example/v1/checkout") in by_key
    assert ("graphql", "orderId", "https://api.example/graphql") in by_key
    assert ("graphql", "filter", "https://api.example/graphql") in by_key


def test_default_pentest_schedules_safe_injection_families() -> None:
    """Default ``ARGUS_ACTIVE_INJECTION_MODE`` is standard — nominal catalog excludes lab-only RCE."""
    s = Settings(_env_file=None)
    assert s.argus_active_injection_mode == "standard"
    assert "rce_commix" not in _nominal_families_for_mode(s.argus_active_injection_mode)
    assert _nominal_families_for_mode(s.argus_active_injection_mode) >= frozenset(
        {"xss", "sqli", "headers"}
    )


def test_quick_mode_limits_to_safe_high_signal_checks() -> None:
    inv = _inventory_multi_surface()
    fq = _flags()
    quick = build_injection_plan(inv, mode="quick", flags=fq)
    std = build_injection_plan(inv, mode="standard", flags=fq)
    assert len(quick) < len(std)
    xss_quick_tools = {s.tool for s in quick if s.family == "xss" and not s.not_assessed_reason}
    xss_std_tools = {s.tool for s in std if s.family == "xss" and not s.not_assessed_reason}
    assert "xsstrike" not in xss_quick_tools
    assert "dalfox" in xss_quick_tools
    assert "xsstrike" in xss_std_tools
    assert not any(s.family == "lfi" and not s.not_assessed_reason for s in quick)
    assert any(s.family == "lfi" and not s.not_assessed_reason for s in std)


def test_standard_mode_schedules_major_safe_families() -> None:
    inv = _inventory_multi_surface()
    steps = build_injection_plan(inv, mode="standard", flags=_flags())
    active = [s for s in steps if not s.not_assessed_reason]
    fams = {s.family for s in active}
    assert {"xss", "sqli", "headers", "lfi"}.issubset(fams)
    assert any(s.family == "sqli" and "graphql" in s.target_url.lower() for s in active)
    assert any(s.family == "xss" and s.tool == "nuclei" for s in active)
    assert any(s.param.lower() == "authorization" for s in active)


def test_deep_mode_schedules_oast_safe_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    inv = _inventory_multi_surface()
    flags_off = _flags(oast=False)
    steps_off = build_injection_plan(inv, mode="deep", flags=flags_off)
    oast_off = [s for s in steps_off if s.family == "oast_ssrf"]
    assert oast_off
    assert all(s.not_assessed_reason == "oast_disabled" for s in oast_off)

    monkeypatch.setattr(core_config.settings, "argus_oast_enabled", True, raising=False)
    monkeypatch.setattr(core_config.settings, "argus_active_injection_mode", "deep", raising=False)
    steps_on = build_injection_plan_from_settings(inv)
    oast_on = [s for s in steps_on if s.family == "oast_ssrf"]
    assert oast_on
    assert all(s.not_assessed_reason is None for s in oast_on)


def test_maximum_mode_requires_lab_and_signed_approval(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(core_config.settings, "argus_lab_mode", False, raising=False)
    assert lab_destructive_execution_allowed(core_config.settings) is False
    inv = _inventory_multi_surface()
    steps = build_injection_plan(inv, mode="maximum", flags=_flags(lab=False, oast=True))
    rce_blocked = [
        s
        for s in steps
        if s.family == "rce_commix"
        and s.not_assessed_reason == "lab_execution_not_authorized"
    ]
    assert rce_blocked
    assert all(s.approval_status == "blocked" for s in rce_blocked)
    assert any(
        s.family == "rce_commix" and s.not_assessed_reason == "family_not_applicable_to_surface_location"
        for s in steps
    )

    d = evaluate_tool_approval_policy("sqlmap", scan_approval_flags={"sqlmap": True})
    assert d.allowed is False
    assert d.reason == "requires_lab_mode"


def test_per_scan_lab_allowed_targets_authorize_owned_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(core_config.settings, "argus_lab_mode", True, raising=False)
    monkeypatch.setattr(core_config.settings, "argus_destructive_lab_mode", True, raising=False)
    monkeypatch.setattr(core_config.settings, "sandbox_enabled", True, raising=False)
    monkeypatch.setattr(core_config.settings, "argus_lab_operator_id", "alex-local-lab", raising=False)
    monkeypatch.setattr(
        core_config.settings,
        "argus_lab_signed_approval_id",
        "lab-approval-2026-04-29-glomsoposten",
        raising=False,
    )
    monkeypatch.setattr(core_config.settings, "argus_kill_switch_required", False, raising=False)
    monkeypatch.setattr(core_config.settings, "argus_lab_allowed_targets", "", raising=False)

    inv = InputSurfaceInventory(
        items=[
            InputSurfaceItem(
                surface_id="login",
                url="https://glomsoposten.vercel.app/api/login",
                method="POST",
                param_name="password",
                location="json",
                source="ui",
                evidence_ref="EV-LAB-001",
            )
        ]
    )
    options = {
        "lab_allowed_targets": [
            "https://glomsoposten.vercel.app",
            "localhost",
            "127.0.0.1",
        ]
    }

    assert _lab_destructive_execution_allowed_for_scan(options, inv) is True
    assert (
        _target_url_matches_scan_lab_allowlist(
            "https://glomsoposten.vercel.app/api/login",
            options,
        )
        is True
    )
    assert (
        _target_url_matches_scan_lab_allowlist(
            "https://unowned.example/api/login",
            options,
        )
        is False
    )


def test_sqlmap_safe_mode_excludes_dump_file_read_os_shell() -> None:
    argv = build_sqlmap_va_argv("https://example.com/item?id=1", None)
    joined = " ".join(argv).lower()
    assert argv
    for forbidden in ("--dump", "--os-shell", "--file-read", "--os-pwn"):
        assert forbidden not in joined


def test_commix_safe_mode_excludes_os_shell() -> None:
    argv = build_commix_va_argv("https://example.com/run", "cmd=1")
    joined = " ".join(argv).lower()
    assert argv[:2] == ["commix", "--url"]
    for forbidden in ("--os-shell", "--os-cmd", "--file-write", "--file-read"):
        assert forbidden not in joined


def test_evidence_xss_reflection_not_confirmed_without_execution() -> None:
    """Alias: XSS reflection not confirmed without execution (spec §10)."""
    f = {
        "title": "Reflected XSS",
        "cwe": "CWE-79",
        "confidence": "confirmed",
        "injection_family": "xss",
        "evidence_refs": ["a1"],
        "proof_of_concept": {"payload": "<svg/onload=1>", "raw_response": "<html><svg"},
    }
    assert has_xss_browser_or_oast_signal(f) is False
    assert any("xss_confirmed_missing_browser_or_oast" in r for r in evaluate_injection_finding_rules(f))


def test_evidence_sqli_time_based_repeated_samples_gate() -> None:
    """Alias: SQLi time-based repeated samples + normalize_evidence_quality (spec §10)."""
    f = {
        "title": "Time-based blind SQLi",
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
    assert any("sqli_time_based_missing_repeated_samples" in r for r in evaluate_injection_finding_rules(f))
    q, notes = normalize_evidence_quality_for_family(
        {**f, "injection_family": "sqli", "evidence_quality": "strong"},
        DEFAULT_INJECTION_EVIDENCE_RULES,
    )
    assert q == "weak"
    assert any("sqli_time_based_without_repeated_samples" in n for n in notes)


def test_evidence_ssrf_xxe_command_injection_rules_via_normalize_evidence_quality() -> None:
    """Alias: SSRF/XXE/command-injection via normalize_evidence_quality_for_family + gate (spec §10)."""
    ssrf = {
        "title": "SSRF",
        "injection_family": "ssrf",
        "confidence": "confirmed",
        "validation_status": "validated",
        "evidence_quality": "strong",
        "evidence_refs": ["e1"],
        "proof_of_concept": {"request_url": "http://internal/"},
    }
    q_ssrf, n_ssrf = normalize_evidence_quality_for_family(ssrf, DEFAULT_INJECTION_EVIDENCE_RULES)
    assert q_ssrf == "weak"
    assert "ssrf_confirmed_without_oast_meta" in n_ssrf
    assert any("ssrf_confirmed_missing_oast" in r for r in evaluate_injection_finding_rules(ssrf))

    xxe = {
        "title": "XXE",
        "cwe": "CWE-611",
        "confidence": "confirmed",
        "evidence_refs": ["x1"],
        "proof_of_concept": {"request_url": "http://x/"},
    }
    q_xxe, n_xxe = normalize_evidence_quality_for_family(
        {**xxe, "injection_family": "xxe"},
        DEFAULT_INJECTION_EVIDENCE_RULES,
    )
    assert q_xxe == "weak"
    assert "xxe_confirmed_without_oast_meta" in n_xxe

    rce = {
        "title": "Command injection",
        "injection_family": "rce",
        "confidence": "confirmed",
        "evidence_refs": ["c1"],
        "proof_of_concept": {"request_url": "http://x/?cmd=ls"},
    }
    q_rce, n_rce = normalize_evidence_quality_for_family(rce, DEFAULT_INJECTION_EVIDENCE_RULES)
    assert q_rce == "weak"
    assert "rce_confirmed_without_oast_meta" in n_rce
    assert has_oast_callback_signal(
        {**rce, "proof_of_concept": {**rce["proof_of_concept"], "oast_callback": True}}
    ) is True


def test_unavailable_tool_marks_family_not_assessed() -> None:
    cov = build_active_injection_coverage(
        [],
        {
            "active_injection_coverage": {
                "families": {
                    "sqli": {"status": "not_assessed", "reason": "tool_binary_missing:sqlmap"},
                },
                "toolsHealth": {"sqlmap": "missing"},
            }
        },
    )
    assert cov["families"]["sqli"]["status"] == "not_assessed"
    row = next(r for r in cov["table_rows"] if r["family"] == "sqli")
    assert row["assessed"] == "no"
    assert "missing" in (row.get("not_assessed_reason") or "").lower() or cov["toolsHealth"].get("sqlmap") == "missing"


def test_plan_coverage_builder_uses_tool_health() -> None:
    inv = _inventory_multi_surface()
    steps = build_injection_plan(inv, mode="standard", flags=_flags(destructive=frozenset({"sqlmap"})))
    cov = build_active_injection_coverage_from_plan(
        steps,
        mode="standard",
        tool_health={
            "dalfox": {"status": "completed"},
            "xsstrike": {"status": "completed"},
            "nuclei": {"status": "completed_no_output"},
            "ffuf": {"status": "failed", "reasons": ["tool_timeout"]},
            "sqlmap": {"status": "skipped", "reasons": ["requires_approval"]},
        },
    )
    assert cov["schema_version"] == "active_injection_coverage_v1"
    assert cov["families"]["xss"]["status"] in {"assessed", "partial"}
    assert cov["families"]["sqli"]["status"] == "not_assessed"
    sqli_row = next(r for r in cov["table_rows"] if r["family"] == "sqli")
    assert sqli_row["assessed"] == "no"
    assert "failed_or_skipped" in sqli_row["not_assessed_reason"]


@pytest.mark.asyncio
async def test_active_scan_phase_populates_scan_options_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(core_config.settings, "sandbox_enabled", True, raising=False)
    monkeypatch.setattr(core_config.settings, "argus_active_injection_mode", "standard", raising=False)
    monkeypatch.setattr(core_config.settings, "argus_oast_enabled", False, raising=False)
    monkeypatch.setattr(core_config.settings, "argus_lab_mode", False, raising=False)
    monkeypatch.setattr(core_config.settings, "argus_destructive_lab_mode", False, raising=False)
    monkeypatch.setattr(core_config.settings, "sqlmap_va_enabled", True, raising=False)
    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="scan-1",
        params_inventory=[
            {
                "full_url": "https://app.example/search?q=1",
                "param_name": "q",
                "method": "GET",
                "location": "query",
            }
        ],
        live_hosts=[{"host": "app.example", "final_url": "https://app.example/"}],
    )
    scan_options: dict = {}
    with (
        patch(
            "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.run_va_active_scan",
            new=AsyncMock(
                return_value={
                    "exit_code": 0,
                    "stdout": "",
                    "stderr": "",
                    "duration_ms": 1,
                    "tool_id": "mock",
                    "error_reason": "",
                }
            ),
        ),
        patch(
            "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.run_owasp003_baseline_checks",
            new=AsyncMock(return_value=[]),
        ),
        patch(
            "src.recon.vulnerability_analysis.active_scan.va_active_scan_phase.enrich_va_intel_poc_visuals",
            new=AsyncMock(return_value=None),
        ),
    ):
        await run_va_active_scan_phase(
            bundle,
            tenant_id_raw=None,
            scan_id_raw="scan-1",
            va_raw_log=lambda _msg: None,
            scan_options=scan_options,
        )
    cov = scan_options.get("active_injection_coverage")
    assert isinstance(cov, dict)
    assert cov["families"]["xss"]["status"] in {"assessed", "partial"}
    assert cov["families"]["sqli"]["status"] == "not_assessed"
    assert any(r["family"] == "xss" for r in cov["table_rows"])


def test_env_examples_document_active_injection_modes() -> None:
    root = Path(__file__).resolve().parents[2]
    for rel in ("../infra/.env.example", ".env.example"):
        text = (root / rel).resolve().read_text(encoding="utf-8")
        assert "ARGUS_ACTIVE_INJECTION_MODE=lab" in text
        assert "ARGUS_LAB_MODE=true" in text
        assert "ARGUS_DESTRUCTIVE_LAB_MODE=true" in text
        assert "ARGUS_KILL_SWITCH_REQUIRED=false" in text
        assert "scan_approval_flags" in text


def test_no_input_surface_marks_family_not_assessed() -> None:
    empty = InputSurfaceInventory(items=[])
    assert build_injection_plan(empty, mode="standard", flags=_flags()) == []
    cov = build_active_injection_coverage(
        [],
        {
            "active_injection_coverage": {
                "families": {
                    "xss": {"status": "not_assessed", "reason": "no_input_surfaces"},
                    "sqli": {"status": "not_assessed", "reason": "no_input_surfaces"},
                },
            }
        },
    )
    for fam in ("xss", "sqli"):
        row = next(r for r in cov["table_rows"] if r["family"] == fam)
        assert row["assessed"] == "no"


def test_injection_coverage_table_populated() -> None:
    findings = [
        {
            "title": "SQL injection",
            "cwe": "CWE-89",
            "confidence": "likely",
            "evidence_refs": ["f1"],
            "proof_of_concept": {"request_url": "https://x.example/p?id=1"},
        }
    ]
    cov = build_active_injection_coverage(findings, None)
    assert cov["table_rows"]
    assert any(r.get("family") == "sqli" and r.get("findings_count", 0) >= 1 for r in cov["table_rows"])


def test_resource_or_force_text_does_not_map_to_rce() -> None:
    cov = build_active_injection_coverage(
        [
            {
                "title": "Missing security response headers",
                "description": "Cross-Origin-Resource-Policy is absent and brute-force risk was not proven.",
                "cwe": "CWE-693",
            }
        ],
        None,
    )
    assert "rce" not in cov["injection_families_observed"]
    assert all(r.get("family") != "rce" for r in cov["table_rows"])


def test_report_does_not_mark_unassessed_family_clean() -> None:
    tpl = Path(__file__).resolve().parents[2] / "src" / "reports" / "templates" / "reports" / "partials" / "valhalla" / "active_injection_coverage.html.j2"
    text = tpl.read_text(encoding="utf-8")
    assert "assessed" in text
    assert "not assessed reason" in text.lower()

    cov = build_active_injection_coverage(
        [{"title": "X", "cwe": "CWE-79", "confidence": "likely", "evidence_refs": ["a"]}],
        {
            "active_injection_coverage": {
                "families": {"xss": {"status": "partial", "reason": "browser_validation_incomplete"}},
            }
        },
    )
    row = next(r for r in cov["table_rows"] if r["family"] == "xss")
    assert row["assessed"] == "partial"
    assert row["assessed"] != "yes"


def test_quality_gate_blocks_confirmed_without_strong_evidence() -> None:
    f = {
        "title": "Blind SQL injection",
        "cwe": "CWE-89",
        "confidence": "confirmed",
        "evidence_refs": ["only-one"],
        "proof_of_concept": {"request_url": "https://x/?id=1"},
    }
    warnings, fail = aggregate_injection_evidence_violations([f])
    assert fail
    assert any("confirmed_without_strong_evidence" in w for w in warnings)
    data = SimpleNamespace(
        valhalla_context=ValhallaReportContext(),
        findings=[f],
        report=None,
        scan=None,
    )
    gate = build_report_quality_gate(data)
    assert gate.injection_evidence_fail is True
    assert any("confirmed_without_strong_evidence" in w for w in gate.injection_evidence_warnings)
