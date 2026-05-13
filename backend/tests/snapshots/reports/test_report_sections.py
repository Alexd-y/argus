"""Tests for individual report section generation — per-tier section sets
and Jinja-oriented context builders.

Validates: tier-to-section mapping, report tier normalisation, Jinja context
construction (without rendering), and active web scan context assembly.
"""

from __future__ import annotations

import pytest

from src.services.reporting import (
    REPORT_TIERS,
    TIER_METADATA,
    _ACTIVE_WEB_SCAN_AI_KEYS_ORDERED,
    _ACTIVE_WEB_SCAN_AI_LABELS,
    _SECTIONS_ASGARD,
    _SECTIONS_MIDGARD,
    _SECTIONS_VALHALLA,
    build_active_web_scan_section_context,
    normalize_report_tier,
    report_tier_sections,
)


class TestReportTierSections:
    """RPT-004 section mapping per tier."""

    def test_midgard_has_two_sections(self) -> None:
        sections = report_tier_sections("midgard")
        assert len(sections) == 2
        assert sections == _SECTIONS_MIDGARD

    def test_asgard_has_five_sections(self) -> None:
        sections = report_tier_sections("asgard")
        assert len(sections) == 5
        assert sections == _SECTIONS_ASGARD

    def test_valhalla_has_twelve_sections(self) -> None:
        sections = report_tier_sections("valhalla")
        assert len(sections) == 12
        assert sections == _SECTIONS_VALHALLA

    def test_unknown_tier_defaults_to_midgard(self) -> None:
        sections = report_tier_sections("unknown")
        assert sections == _SECTIONS_MIDGARD

    def test_empty_string_defaults_to_midgard(self) -> None:
        sections = report_tier_sections("")
        assert sections == _SECTIONS_MIDGARD

    @pytest.mark.parametrize("tier", ["midgard", "asgard", "valhalla"])
    def test_each_tier_section_key_is_non_empty(self, tier: str) -> None:
        sections = report_tier_sections(tier)
        for section_key in sections:
            assert section_key, f"{tier} section key is empty"
            assert isinstance(section_key, str)


class TestNormalizeReportTier:
    """`normalize_report_tier` handles edge cases."""

    def test_normalize_recognised_tiers(self) -> None:
        assert normalize_report_tier("midgard") == "midgard"
        assert normalize_report_tier("asgard") == "asgard"
        assert normalize_report_tier("valhalla") == "valhalla"

    def test_normalize_case_insensitive(self) -> None:
        assert normalize_report_tier("MIDGARD") == "midgard"
        assert normalize_report_tier("Asgard") == "asgard"
        assert normalize_report_tier("VALHALLA") == "valhalla"

    def test_normalize_unknown_falls_back(self) -> None:
        assert normalize_report_tier("bifrost") == "midgard"
        assert normalize_report_tier(None) == "midgard"  # type: ignore[arg-type]

    def test_normalize_whitespace(self) -> None:
        assert normalize_report_tier("  asgard  ") == "midgard"


class TestTierMetadata:
    """TIER_METADATA must be consistent with REPORT_TIERS."""

    def test_all_tiers_have_metadata(self) -> None:
        for tier in REPORT_TIERS:
            assert tier in TIER_METADATA, f"Missing metadata for {tier}"

    def test_each_metadata_has_label(self) -> None:
        for tier, meta in TIER_METADATA.items():
            assert isinstance(meta.get("label"), str)
            assert len(meta["label"]) > 0

    def test_metadata_has_focus_field(self) -> None:
        for tier, meta in TIER_METADATA.items():
            assert "focus" in meta, f"Missing focus for {tier}"

    def test_asgard_and_valhalla_have_active_web_scan(self) -> None:
        assert TIER_METADATA["asgard"]["active_web_scan"] is True
        assert TIER_METADATA["valhalla"]["active_web_scan"] is True

    def test_midgard_no_active_web_scan(self) -> None:
        assert TIER_METADATA["midgard"]["active_web_scan"] is False


class TestActiveWebScanSections:
    """OWASP2-007 active web scan context builder."""

    def test_ai_keys_are_ordered_and_labeled(self) -> None:
        assert len(_ACTIVE_WEB_SCAN_AI_KEYS_ORDERED) == 5
        for key in _ACTIVE_WEB_SCAN_AI_KEYS_ORDERED:
            assert key in _ACTIVE_WEB_SCAN_AI_LABELS

    def test_visible_for_asgard_when_no_signals(self) -> None:
        ctx = build_active_web_scan_section_context(
            "asgard",
            {"phase_blocks": []},
            {},
        )
        assert ctx["visible"] is True
        assert ctx["tier"] == "asgard"
        assert ctx["tools_run"] == []
        assert ctx["has_signals"] is False

    def test_not_visible_for_midgard_when_no_signals(self) -> None:
        ctx = build_active_web_scan_section_context(
            "midgard",
            {"phase_blocks": []},
            {},
        )
        assert ctx["visible"] is False

    def test_visible_for_valhalla_when_no_signals(self) -> None:
        ctx = build_active_web_scan_section_context(
            "valhalla",
            {"phase_blocks": []},
            {},
        )
        assert ctx["visible"] is True

    def test_tool_names_extracted_from_artifacts(self) -> None:
        artifacts = {
            "phase_blocks": [
                {
                    "phase_key": "vuln_analysis",
                    "rows": [
                        {"file_name": "20250512T120000_abcdef123456_tool_nuclei_scan_results.json"},
                        {"file_name": "20250512T120001_abcdef789abc_tool_sqlmap_celery_results.txt"},
                    ],
                },
            ]
        }
        ctx = build_active_web_scan_section_context(
            "asgard",
            artifacts,
            {},
        )
        assert "nuclei" in ctx["tools_run"]
        assert "sqlmap" in ctx["tools_run"]

    def test_ai_summary_rows_skip_placeholder_texts(self) -> None:
        from src.reports.ai_text_generation import (
            REPORT_AI_SKIPPED_NO_LLM,
        )
        from src.orchestration.prompt_registry import (
            REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS,
        )

        ai_texts = {REPORT_AI_SECTION_HARDENING_RECOMMENDATIONS: REPORT_AI_SKIPPED_NO_LLM}
        ctx = build_active_web_scan_section_context(
            "valhalla",
            {"phase_blocks": []},
            ai_texts,
        )
        assert len(ctx["ai_summary_rows"]) == 0

    def test_curl_xss_example_present_in_context(self) -> None:
        from src.services.reporting import ACTIVE_WEB_SCAN_CURL_XSS_EXAMPLE

        assert "curl" in ACTIVE_WEB_SCAN_CURL_XSS_EXAMPLE

        ctx = build_active_web_scan_section_context("asgard", {"phase_blocks": []}, {})
        assert ctx["curl_xss_example"] == ACTIVE_WEB_SCAN_CURL_XSS_EXAMPLE
