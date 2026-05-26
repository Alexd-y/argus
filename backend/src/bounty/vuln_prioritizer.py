"""Vulnerability prioritiser — rank vulnerability types by typical bounty payout."""

from __future__ import annotations

from src.bounty.schemas import BountyScope, VulnPriority


VULN_PRIORITY: list[VulnPriority] = [
    VulnPriority(vuln="RCE", score=10, owasp="A05", test_module="api_checks"),
    VulnPriority(vuln="SQL Injection", score=10, owasp="A05", test_module="quick_fuzz"),
    VulnPriority(vuln="SSRF", score=9, owasp="A05", test_module="quick_fuzz"),
    VulnPriority(vuln="Authentication Bypass", score=9, owasp="A07", test_module="auth_audit"),
    VulnPriority(vuln="IDOR/BOLA", score=8, owasp="A01", test_module="bola"),
    VulnPriority(vuln="XSS (Stored)", score=8, owasp="A05", test_module="quick_fuzz"),
    VulnPriority(vuln="XXE", score=7, owasp="A05", test_module="quick_fuzz"),
    VulnPriority(vuln="Privilege Escalation", score=7, owasp="A01", test_module="auth_audit"),
    VulnPriority(vuln="Business Logic", score=7, owasp="A06", test_module="api_checks"),
    VulnPriority(vuln="CSRF", score=6, owasp="A06", test_module="api_checks"),
    VulnPriority(vuln="XSS (Reflected)", score=5, owasp="A05", test_module="quick_fuzz"),
    VulnPriority(vuln="Prompt Injection", score=5, owasp="A05", test_module="quick_fuzz"),
    VulnPriority(vuln="Open Redirect", score=4, owasp="A01", test_module="recon"),
    VulnPriority(vuln="Info Disclosure", score=3, owasp="A09", test_module="recon"),
    VulnPriority(vuln="Missing Headers", score=2, owasp="A02", test_module="recon"),
    VulnPriority(vuln="Rate Limiting", score=2, owasp="A06", test_module="api_checks"),
]


def prioritize_vulns(scope: BountyScope) -> list[VulnPriority]:
    """Return prioritised vulnerability list based on scope."""
    accepted = [v.lower() for v in scope.vulnerability_types] if scope.vulnerability_types else []
    excluded = [v.lower() for v in scope.excluded_vuln_types]

    results: list[VulnPriority] = []
    for vp in VULN_PRIORITY:
        if accepted and not any(a in vp.vuln.lower() for a in accepted):
            continue
        if any(e in vp.vuln.lower() for e in excluded):
            continue
        results.append(vp)

    return sorted(results, key=lambda x: x.score, reverse=True)