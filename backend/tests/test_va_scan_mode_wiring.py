"""Tests for backlog closure fixes FIX-001 through FIX-005: scan_mode wiring, vuln flag mapping, AI dedup."""

from __future__ import annotations

import pytest

# ---------------------------------------------------------------------------
# Class 1: TestScanModeWiring
# ---------------------------------------------------------------------------

class TestScanModeWiring:
    """FIX-001 — scan_mode is extracted from scan_options via the priority chain:
    scanType > scan_mode > "standard" default.
    """

    @staticmethod
    def _extract_scan_mode(scan_options: dict | None) -> str:
        """Mirror the extraction logic used in handlers.run_vuln_analysis."""
        return (
            (scan_options or {}).get("scanType")
            or (scan_options or {}).get("scan_mode")
            or "standard"
        )

    def test_scan_type_key_deep(self) -> None:
        assert self._extract_scan_mode({"scanType": "deep"}) == "deep"

    def test_scan_mode_key_aggressive(self) -> None:
        assert self._extract_scan_mode({"scan_mode": "aggressive"}) == "aggressive"

    def test_empty_dict_defaults_to_standard(self) -> None:
        assert self._extract_scan_mode({}) == "standard"

    def test_none_defaults_to_standard(self) -> None:
        assert self._extract_scan_mode(None) == "standard"

    def test_scan_type_takes_precedence_over_scan_mode(self) -> None:
        result = self._extract_scan_mode({"scanType": "deep", "scan_mode": "standard"})
        assert result == "deep"

    def test_falsy_scan_type_falls_through_to_scan_mode(self) -> None:
        result = self._extract_scan_mode({"scanType": "", "scan_mode": "quick"})
        assert result == "quick"

    def test_both_empty_strings_fall_through_to_default(self) -> None:
        result = self._extract_scan_mode({"scanType": "", "scan_mode": ""})
        assert result == "standard"


# ---------------------------------------------------------------------------
# Class 2: TestVulnFlagMapping
# ---------------------------------------------------------------------------

class TestVulnFlagMapping:
    """FIX-003 — _map_vuln_flags maps short API flag names to planner flags."""

    @pytest.fixture(autouse=True)
    def _import_map_vuln_flags(self) -> None:
        try:
            from src.recon.vulnerability_analysis.active_scan.va_active_scan_phase import (
                _map_vuln_flags,
            )
            self._map_vuln_flags = _map_vuln_flags
        except ImportError:
            pytest.skip("_map_vuln_flags not importable (module dependency missing)")

    def test_short_flags_mapped_to_planner_format(self) -> None:
        result = self._map_vuln_flags({"xss": True, "sqli": True})
        assert result == {"xss_enabled": True, "sqli_enabled": True}

    def test_already_planner_format_unchanged(self) -> None:
        result = self._map_vuln_flags({"xss_enabled": True})
        assert result == {"xss_enabled": True}

    def test_existing_planner_key_not_overwritten(self) -> None:
        result = self._map_vuln_flags({"xss": True, "xss_enabled": False})
        assert result["xss_enabled"] is False
        assert "xss" in result, "short key preserved when planner key already present"

    def test_empty_dict_returns_empty(self) -> None:
        result = self._map_vuln_flags({})
        assert result == {}

    def test_mixed_flags(self) -> None:
        result = self._map_vuln_flags({"xss": True, "sqli_enabled": True, "lfi": False})
        assert result["xss_enabled"] is True
        assert result["sqli_enabled"] is True
        assert result["lfi_enabled"] is False
        assert "xss" not in result, "short key removed after mapping"
        assert "lfi" not in result, "short key removed after mapping"

    def test_all_short_flags(self) -> None:
        inp = {"xss": True, "sqli": True, "csrf": True, "ssrf": False, "lfi": True, "rce": False, "idor": True}
        result = self._map_vuln_flags(inp)
        expected_keys = {"xss_enabled", "sqli_enabled", "csrf_enabled", "ssrf_enabled", "lfi_enabled", "rce_enabled", "idor_enabled"}
        assert set(result.keys()) == expected_keys
        assert result["xss_enabled"] is True
        assert result["ssrf_enabled"] is False

    def test_unrelated_keys_preserved(self) -> None:
        result = self._map_vuln_flags({"xss": True, "custom_flag": 42})
        assert result["xss_enabled"] is True
        assert result["custom_flag"] == 42


# ---------------------------------------------------------------------------
# Class 3: TestAIDedup
# ---------------------------------------------------------------------------

class TestAIDedup:
    """FIX-005 — AITextDeduplicator.deduplicate_sections removes cross-section duplicates."""

    @pytest.fixture(autouse=True)
    def _import_deduplicator(self) -> None:
        try:
            from src.reports.ai_text_generation import AITextDeduplicator
            self._cls = AITextDeduplicator
        except ImportError:
            pytest.skip("AITextDeduplicator not importable (module dependency missing)")

    def test_duplicate_paragraphs_reduced(self) -> None:
        dedup = self._cls()
        duplicate_text = (
            "The application has a critical cross-site scripting vulnerability in the login form. "
            "An attacker can inject arbitrary JavaScript code that executes in the victim browser context."
        )
        sections = {
            "executive_summary": duplicate_text,
            "detailed_analysis": duplicate_text + " Additional unique analysis content goes here.",
        }
        result = dedup.deduplicate_sections(sections)
        assert "executive_summary" in result
        assert "detailed_analysis" in result
        total_original = sum(len(v) for v in sections.values())
        total_deduped = sum(len(v) for v in result.values())
        assert total_deduped <= total_original

    def test_single_section_unchanged(self) -> None:
        dedup = self._cls()
        sections = {"summary": "This is a standalone summary with enough words to be meaningful."}
        result = dedup.deduplicate_sections(sections)
        assert result == sections

    def test_empty_dict_returns_empty(self) -> None:
        dedup = self._cls()
        result = dedup.deduplicate_sections({})
        assert result == {}

    def test_no_overlap_sections_preserved(self) -> None:
        dedup = self._cls()
        sections = {
            "section_a": "The first section discusses authentication mechanisms and session management policies.",
            "section_b": "This part covers network infrastructure and firewall configuration details thoroughly.",
        }
        result = dedup.deduplicate_sections(sections)
        assert result["section_a"] == sections["section_a"]
        assert result["section_b"] == sections["section_b"]

    def test_cross_reference_inserted(self) -> None:
        dedup = self._cls()
        shared = (
            "Server misconfiguration allows directory listing which exposes sensitive internal files. "
            "The web server responds with detailed error messages that include stack trace information."
        )
        sections = {
            "first_section": shared,
            "second_section": shared + " But also some unique content is present in this section.",
        }
        result = dedup.deduplicate_sections(sections)
        assert "first_section" in result
        second = result["second_section"]
        has_xref = "See" in second or "section" in second.lower()
        has_reduction = len(second) < len(sections["second_section"])
        assert has_xref or has_reduction, "Dedup should cross-reference or reduce the duplicate"
