"""Regression tests for CWE/category domain routing (platform-hardening-A, 3.2).

Behaviour-level tests (not source-string checks) for
``vuln_agents.filter_findings_by_domain`` and its normalisation helpers.
"""

from __future__ import annotations

import pytest
from src.orchestration.vuln_agents import (
    AgentDomain,
    _normalize_category,
    _normalize_cwes,
    build_agent_tasks,
    filter_findings_by_domain,
)


class TestCweNormalization:
    def test_int(self):
        assert _normalize_cwes(89) == [89]

    def test_numeric_string(self):
        assert _normalize_cwes("89") == [89]

    def test_cwe_prefixed_string(self):
        assert _normalize_cwes("CWE-79") == [79]
        assert _normalize_cwes("cwe_918") == [918]
        assert _normalize_cwes("CWE 287") == [287]

    def test_list_mixed(self):
        assert _normalize_cwes([89, "CWE-79", "918"]) == [89, 79, 918]

    def test_missing(self):
        assert _normalize_cwes(None) == []
        assert _normalize_cwes([]) == []

    def test_invalid_values_skipped(self):
        assert _normalize_cwes("supply-chain") == []
        assert _normalize_cwes(["abc", None, 89]) == [89]

    def test_bool_is_not_cwe(self):
        # ``bool`` subclasses ``int`` — must not be read as CWE 1/0.
        assert _normalize_cwes(True) == []
        assert _normalize_cwes([True, 89]) == [89]


class TestCategoryNormalization:
    def test_collapses_separators(self):
        assert _normalize_category("SQL-Injection") == "sql injection"
        assert _normalize_category("broken_access_control") == "broken access control"

    def test_empty(self):
        assert _normalize_category("") == ""
        assert _normalize_category(None) == ""
        assert _normalize_category("   ") == ""


class TestDomainRouting:
    def test_empty_category_matches_no_domain(self):
        """The original bug: ``category in domain_lower`` matched every domain."""
        findings = [{"title": "unknown", "category": "", "cwe": None}]
        for domain in AgentDomain:
            assert filter_findings_by_domain(findings, domain) == []

    def test_cwe_routes_to_correct_domain_only(self):
        findings = [{"title": "SQLi", "cwe": [89]}]
        assert len(filter_findings_by_domain(findings, AgentDomain.INJECTION)) == 1
        assert filter_findings_by_domain(findings, AgentDomain.XSS) == []
        assert filter_findings_by_domain(findings, AgentDomain.SSRF) == []

    def test_cwe_string_forms_route(self):
        findings = [{"title": "XSS", "cwe": "CWE-79"}]
        assert len(filter_findings_by_domain(findings, AgentDomain.XSS)) == 1
        assert filter_findings_by_domain(findings, AgentDomain.INJECTION) == []

    def test_category_exact_match_only(self):
        findings = [{"title": "SQLi", "category": "sql injection"}]
        assert len(filter_findings_by_domain(findings, AgentDomain.INJECTION)) == 1
        assert filter_findings_by_domain(findings, AgentDomain.XSS) == []

    def test_auth_vs_authz_not_confused(self):
        """``auth`` is a substring of ``authorization`` but they are distinct."""
        auth_finding = [{"title": "Broken auth", "category": "authentication"}]
        authz_finding = [{"title": "IDOR", "category": "authorization"}]

        assert len(filter_findings_by_domain(auth_finding, AgentDomain.AUTH)) == 1
        assert filter_findings_by_domain(auth_finding, AgentDomain.AUTHZ) == []

        assert len(filter_findings_by_domain(authz_finding, AgentDomain.AUTHZ)) == 1
        assert filter_findings_by_domain(authz_finding, AgentDomain.AUTH) == []

    def test_unknown_category_matches_nothing(self):
        findings = [{"title": "leak", "category": "information-disclosure", "cwe": None}]
        for domain in AgentDomain:
            assert filter_findings_by_domain(findings, domain) == []

    def test_multiple_domains_on_explicit_grounds(self):
        # A finding carrying two focus CWEs (injection + ssrf) legitimately
        # routes to both domains.
        findings = [{"title": "SSRF via cmd", "cwe": [78, 918]}]
        assert len(filter_findings_by_domain(findings, AgentDomain.INJECTION)) == 1
        assert len(filter_findings_by_domain(findings, AgentDomain.SSRF)) == 1
        assert filter_findings_by_domain(findings, AgentDomain.XSS) == []

    def test_no_intra_domain_duplication(self):
        # Same finding, both a focus CWE and a matching category -> counted once.
        findings = [{"title": "SQLi", "cwe": [89], "category": "sql injection"}]
        assert len(filter_findings_by_domain(findings, AgentDomain.INJECTION)) == 1

    def test_distinct_findings_equal_content_both_kept(self):
        # Identity-based dedup: two separate dicts with equal content are kept.
        findings = [
            {"title": "SQLi", "cwe": [89]},
            {"title": "SQLi", "cwe": [89]},
        ]
        assert len(filter_findings_by_domain(findings, AgentDomain.INJECTION)) == 2

    def test_build_agent_tasks_routes_by_domain(self):
        findings = [
            {"cwe": [89], "title": "SQL Injection"},
            {"cwe": [79], "title": "XSS"},
            {"cwe": [918], "title": "SSRF"},
        ]
        tasks = build_agent_tasks("target-under-test", findings, scan_id="scan-1")
        domains = {t["domain"] for t in tasks}
        # CWE-918 is in both the SSRF and AUTHZ focus sets (SSRF frequently
        # overlaps broken access control), so routing to both is correct.
        assert {"injection", "xss", "ssrf"} <= domains
        assert domains <= {"injection", "xss", "ssrf", "authz"}

    def test_build_agent_tasks_empty_when_no_routable_findings(self):
        findings = [{"title": "misc", "category": "information-disclosure"}]
        assert build_agent_tasks("target-under-test", findings) == []


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
