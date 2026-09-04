"""Block 3 — baseline coverage vs pass_rate evaluator tests."""

from __future__ import annotations

from src.reports.baseline import evaluate_baseline, load_baseline_controls

_CONTROL_IDS = {"tls", "open_ports", "dns", "mail_headers", "security_headers"}


def _by_id(result):
    return {c["id"]: c for c in result["controls"]}


def test_controls_loaded_from_yaml():
    ids = {c["id"] for c in load_baseline_controls()}
    assert _CONTROL_IDS.issubset(ids)


def test_empty_scan_all_not_assessed():
    r = evaluate_baseline([], {})
    assert r["coverage"] == 0.0
    assert r["pass_rate"] == 0.0
    assert all(c["status"] == "not_assessed" for c in r["controls"])


def test_weak_domain_high_coverage_low_pass_rate():
    findings = [
        {"title": "TLS configuration weakness", "source_tool": "testssl", "severity": "medium"},
        {"title": "Incomplete security HTTP headers", "severity": "low"},
        {"title": "SPF record missing", "source_tool": "dns_recon", "severity": "medium"},
    ]
    recon = {"ports": [443], "subdomains": ["www.alleksy.com"]}
    r = evaluate_baseline(findings, recon)
    controls = _by_id(r)
    # All five executed (tls via 443/finding, open_ports via 443, dns via subs,
    # mail via SPF finding, headers via finding).
    assert r["executed"] == 5
    assert controls["tls"]["status"] == "fail"           # medium weakness
    assert controls["open_ports"]["status"] == "pass"    # 443 enumerated
    assert controls["dns"]["status"] == "pass"           # no high DNS issue
    assert controls["mail_headers"]["status"] == "fail"  # SPF missing
    assert controls["security_headers"]["status"] == "fail"
    assert r["coverage"] == 1.0
    assert r["pass_rate"] == 0.4  # only open_ports + dns pass -> 2/5


def test_open_axfr_fails_dns_control():
    findings = [
        {"title": "DNS zone transfer (AXFR) allowed", "source_tool": "dig_axfr", "severity": "high"},
    ]
    r = evaluate_baseline(findings, {"ports": [53]})
    assert _by_id(r)["dns"]["status"] == "fail"


def test_clean_domain_via_overrides_all_pass():
    # No findings, but the reporting phase asserts all checks ran.
    r = evaluate_baseline([], {"ports": [443]}, executed_overrides=set(_CONTROL_IDS))
    assert r["executed"] == 5
    assert r["passed"] == 5
    assert r["coverage"] == 1.0
    assert r["pass_rate"] == 1.0
    assert all(c["status"] == "pass" for c in r["controls"])


def test_partial_coverage():
    # Only TLS + open_ports ran (443 live, clean TLS); mail/dns/headers skipped.
    r = evaluate_baseline([], {"ports": [443]}, executed_overrides={"tls", "open_ports"})
    assert r["executed"] == 2
    assert r["coverage"] == 0.4
    controls = _by_id(r)
    assert controls["mail_headers"]["status"] == "not_assessed"
    assert controls["tls"]["status"] == "pass"


def test_tls_info_probe_only_is_pass():
    # An informational TLS_PROBE with no weakness should not fail the control.
    findings = [{"title": "TLS_PROBE finding", "source_tool": "testssl", "severity": "info"}]
    r = evaluate_baseline(findings, {"ports": [443]})
    assert _by_id(r)["tls"]["status"] == "pass"
