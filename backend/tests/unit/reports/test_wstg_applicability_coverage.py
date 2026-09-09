"""WSTG applicability + strict-gate coverage (Track B, >80% goal).

Proves that with rationale-backed applicability exclusions (spec §4) and
evidence-linked findings, a representative Full-Surface run scores >80% strict
coverage — and that a reduced toolset still clears the 80% gate.
"""

from __future__ import annotations

from src.reports.wstg_applicability import infer_wstg_applicability
from src.reports.wstg_gate import COVERAGE_GATE_THRESHOLD, compute_wstg_coverage
from src.reports.wstg_plan import build_engagement_test_plan, derive_wstg_states

# Passive + active suite a Full-Surface scan runs against a static, unauth site.
_FULL_TOOLS = [
    "nmap", "naabu", "httpx", "whatweb", "wappalyzer", "testssl", "sslscan",
    "nuclei", "nikto", "ffuf", "feroxbuster", "katana", "waybackurls", "gau",
    "subfinder", "amass", "dnsrecon", "dig", "wafw00f", "arjun", "curl",
    "theharvester", "trivy", "retire.js", "playwright", "gitleaks",
]

# A leaner run (some optional tools unavailable) — must still pass the gate.
_REDUCED_TOOLS = [
    "nmap", "httpx", "whatweb", "testssl", "nuclei", "nikto", "ffuf",
    "subfinder", "curl", "dnsrecon",
]

# Representative evidenced findings for a static/unauth site.
_FINDINGS = [
    {
        "id": "F1", "title": "Missing security headers", "vuln_type": "security_headers",
        "cwe": "CWE-693", "_has_evidence": True,
        "proof_of_concept": {"observed": "no HSTS"},
    },
    {
        "id": "F2", "title": "No rate limiting on endpoint", "vuln_type": "rate_limit",
        "cwe": "CWE-307", "_has_evidence": True, "evidence_refs": ["ev-1"],
    },
    {
        "id": "F3", "title": "Subdomain enumeration exposure", "vuln_type": "subdomain",
        "wstg": "WSTG-CONF-10", "_has_evidence": True, "evidence_refs": ["ev-2"],
    },
    {
        "id": "F4", "title": "SPF/DMARC misconfiguration", "cwe": "CWE-16",
        "_has_evidence": True, "proof_of_concept": {"record": "v=spf1 ~all"},
    },
]


def _evidence_by_test(findings):
    from src.reports.wstg_coverage import wstg_ids_for_finding

    ev: dict[str, list[str]] = {}
    for f in findings:
        if not f.get("_has_evidence"):
            continue
        for wid in wstg_ids_for_finding(f):
            ev.setdefault(wid, []).append(f"FINDING:{f['id']}")
    return ev


def _coverage(tools):
    applicability, rationale = infer_wstg_applicability(
        authenticated=False, has_input_surface=False, has_cookies=False
    )
    plan = build_engagement_test_plan(
        applicability=applicability, exclusion_rationale=rationale
    )
    states = derive_wstg_states(
        tools, _FINDINGS, base_plan=plan, evidence_by_test=_evidence_by_test(_FINDINGS)
    )
    return compute_wstg_coverage(states, catalog_size=len(states))


class TestApplicability:
    def test_unauth_static_excludes_auth_and_input(self):
        app, rat = infer_wstg_applicability(
            authenticated=False, has_input_surface=False, has_cookies=False
        )
        # Every exclusion carries a written rationale (audited, no silent drops).
        assert set(app) == set(rat)
        assert app["WSTG-ATHN-02"] is False  # auth-dependent
        assert app["WSTG-INPV-05"] is False  # input-dependent (SQLi)
        assert app["WSTG-SESS-02"] is False  # cookie-dependent
        assert "WSTG-INFO-02" not in app     # always applicable

    def test_authenticated_keeps_auth_tests(self):
        app, _ = infer_wstg_applicability(
            authenticated=True, has_input_surface=True, has_cookies=True
        )
        assert "WSTG-ATHN-02" not in app
        assert "WSTG-INPV-05" not in app


class TestStrictCoverage:
    def test_full_toolset_exceeds_80_percent(self):
        report = _coverage(_FULL_TOOLS)
        assert report.coverage_pct > COVERAGE_GATE_THRESHOLD
        assert report.gate_passed is True
        assert not report.exclusion_errors

    def test_reduced_toolset_still_passes_gate(self):
        report = _coverage(_REDUCED_TOOLS)
        assert report.coverage_pct > COVERAGE_GATE_THRESHOLD

    def test_no_unjustified_exclusions(self):
        report = _coverage(_FULL_TOOLS)
        # applicable denominator is honest (< full catalog, > 0)
        assert 0 < report.applicable < report.catalog_size
