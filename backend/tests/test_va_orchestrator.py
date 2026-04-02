"""Tests for the Multi-Agent VA Orchestrator (ENH-V3)."""

import pytest

from src.agents.va_orchestrator import (
    CATEGORY_SKILL_MAP,
    REASONING_EFFORT,
    ScanMode,
    VAMultiAgentOrchestrator,
)


class TestScanMode:
    def test_quick_mode(self):
        orch = VAMultiAgentOrchestrator("quick")
        assert orch.scan_mode == ScanMode.QUICK
        assert orch.temperature == 0.3

    def test_standard_mode(self):
        orch = VAMultiAgentOrchestrator("standard")
        assert orch.scan_mode == ScanMode.STANDARD
        assert orch.temperature == 0.2

    def test_deep_mode(self):
        orch = VAMultiAgentOrchestrator("deep")
        assert orch.scan_mode == ScanMode.DEEP
        assert orch.temperature == 0.1

    def test_invalid_mode_falls_back_to_standard(self):
        orch = VAMultiAgentOrchestrator("invalid")
        assert orch.scan_mode == ScanMode.STANDARD


class TestDetermineCategories:
    def test_quick_has_4_categories(self):
        orch = VAMultiAgentOrchestrator("quick")
        cats = orch.determine_categories()
        assert len(cats) == 4
        assert "sqli" in cats
        assert "xss" in cats
        assert "auth" in cats
        assert "idor" in cats
        assert "ssrf" not in cats

    def test_standard_has_8_categories(self):
        orch = VAMultiAgentOrchestrator("standard")
        cats = orch.determine_categories()
        assert len(cats) == 8
        assert "sqli" in cats
        assert "ssrf" in cats
        assert "rce" in cats
        assert "csrf" in cats

    def test_deep_has_all_categories(self):
        orch = VAMultiAgentOrchestrator("deep")
        cats = orch.determine_categories()
        assert len(cats) == len(CATEGORY_SKILL_MAP)

    def test_updates_stats(self):
        orch = VAMultiAgentOrchestrator("quick")
        orch.determine_categories()
        assert len(orch.stats.categories_tested) == 4


class TestGetUntestedCategories:
    def test_quick_has_untested(self):
        orch = VAMultiAgentOrchestrator("quick")
        orch.determine_categories()
        untested = orch.get_untested_categories()
        assert "ssrf" in untested
        assert "rce" in untested
        assert len(untested) == len(CATEGORY_SKILL_MAP) - 4

    def test_deep_has_no_untested(self):
        orch = VAMultiAgentOrchestrator("deep")
        orch.determine_categories()
        untested = orch.get_untested_categories()
        assert untested == []


class TestOrchestratorStats:
    def test_noise_reduction_pct(self):
        orch = VAMultiAgentOrchestrator("deep")
        orch.stats.findings_total = 100
        orch.stats.findings_rejected = 20
        orch.stats.findings_deduplicated = 10
        assert orch.stats.noise_reduction_pct == 30.0

    def test_noise_reduction_pct_zero_total(self):
        orch = VAMultiAgentOrchestrator("deep")
        orch.stats.findings_total = 0
        assert orch.stats.noise_reduction_pct == 0.0

    def test_owasp_coverage_pct(self):
        orch = VAMultiAgentOrchestrator("quick")
        orch.determine_categories()
        pct = orch.stats.owasp_coverage_pct
        expected = round(4 / len(CATEGORY_SKILL_MAP) * 100, 1)
        assert pct == expected


class TestParseFindings:
    def test_parse_json_array(self):
        orch = VAMultiAgentOrchestrator("standard")
        text = '[{"title": "SQLi", "severity": "high"}]'
        findings = orch._parse_findings(text, "sqli", "https://target.com")
        assert len(findings) == 1
        assert findings[0]["title"] == "SQLi"
        assert findings[0]["category"] == "sqli"

    def test_parse_json_with_fences(self):
        orch = VAMultiAgentOrchestrator("standard")
        text = '```json\n[{"title": "XSS"}]\n```'
        findings = orch._parse_findings(text, "xss", "https://target.com")
        assert len(findings) == 1

    def test_parse_invalid_returns_empty(self):
        orch = VAMultiAgentOrchestrator("standard")
        text = "This is not JSON at all"
        findings = orch._parse_findings(text, "sqli", "https://target.com")
        assert findings == []

    def test_parse_embedded_json_in_text(self):
        orch = VAMultiAgentOrchestrator("standard")
        text = 'Here are the findings:\n[{"title": "CSRF", "severity": "medium"}]\nDone.'
        findings = orch._parse_findings(text, "csrf", "https://target.com")
        assert len(findings) == 1
        assert findings[0]["title"] == "CSRF"
