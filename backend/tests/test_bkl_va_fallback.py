"""BKL-002: VA fallback output for web_scan_planning and generic_web_finding.

Tests:
- _build_va_fallback_output("web_scan_planning", ...) returns dict with "invocations" key
- _build_va_fallback_output("generic_web_finding", ...) returns dict with "findings" key
- _build_va_task_input includes bundle for both tasks
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from src.recon.vulnerability_analysis.pipeline import (
    _build_va_fallback_output,
    _build_va_task_input,
)


def _make_minimal_bundle() -> MagicMock:
    """Create a minimal VulnerabilityAnalysisInputBundle mock."""
    bundle = MagicMock()
    bundle.entry_points = []
    bundle.api_surface = []
    bundle.intel_findings = []
    bundle.params_inventory = []
    bundle.forms_inventory = []
    bundle.route_inventory = []
    bundle.js_findings = []
    bundle.anomalies = []
    bundle.trust_boundaries = []
    bundle.threat_scenarios = []
    bundle.live_hosts = []
    bundle.tech_profile = []
    bundle.model_dump.return_value = {
        "entry_points": [],
        "api_surface": [],
        "intel_findings": [],
    }
    return bundle


class TestBuildVaFallbackOutputWebScanPlanning:
    """BKL-002: web_scan_planning fallback must produce invocations list."""

    def test_returns_dict_with_invocations_key(self) -> None:
        bundle = _make_minimal_bundle()
        result = _build_va_fallback_output("web_scan_planning", bundle, {})
        assert isinstance(result, dict)
        assert "invocations" in result

    def test_invocations_is_list(self) -> None:
        bundle = _make_minimal_bundle()
        result = _build_va_fallback_output("web_scan_planning", bundle, {})
        assert isinstance(result["invocations"], list)

    def test_invocations_nonempty_fallback(self) -> None:
        bundle = _make_minimal_bundle()
        result = _build_va_fallback_output("web_scan_planning", bundle, {})
        assert len(result["invocations"]) >= 1

    def test_invocations_entry_has_tool_name(self) -> None:
        bundle = _make_minimal_bundle()
        result = _build_va_fallback_output("web_scan_planning", bundle, {})
        for inv in result["invocations"]:
            assert "tool_name" in inv

    def test_invocations_with_entry_points(self) -> None:
        bundle = _make_minimal_bundle()
        ep = MagicMock()
        ep.host_or_component = "http://example.com/login"
        ep.name = "login"
        ep.id = "ep_0"
        bundle.entry_points = [ep]
        result = _build_va_fallback_output("web_scan_planning", bundle, {})
        assert len(result["invocations"]) >= 1
        assert "example.com" in result["invocations"][0].get("target_url", "")


class TestBuildVaFallbackOutputGenericWebFinding:
    """BKL-002: generic_web_finding fallback must produce findings list."""

    def test_returns_dict_with_findings_key(self) -> None:
        bundle = _make_minimal_bundle()
        result = _build_va_fallback_output("generic_web_finding", bundle, {})
        assert isinstance(result, dict)
        assert "findings" in result

    def test_findings_is_list(self) -> None:
        bundle = _make_minimal_bundle()
        result = _build_va_fallback_output("generic_web_finding", bundle, {})
        assert isinstance(result["findings"], list)

    def test_findings_nonempty_fallback(self) -> None:
        bundle = _make_minimal_bundle()
        result = _build_va_fallback_output("generic_web_finding", bundle, {})
        assert len(result["findings"]) >= 1

    def test_findings_with_intel(self) -> None:
        bundle = _make_minimal_bundle()
        bundle.intel_findings = [
            {
                "description": "Test finding",
                "type": "web_misc",
                "url": "http://example.com",
                "severity": "medium",
            }
        ]
        result = _build_va_fallback_output("generic_web_finding", bundle, {})
        assert len(result["findings"]) >= 1
        found = result["findings"][0]
        assert "description" in found

    def test_finding_entry_has_description(self) -> None:
        bundle = _make_minimal_bundle()
        result = _build_va_fallback_output("generic_web_finding", bundle, {})
        for f in result["findings"]:
            assert "description" in f


class TestBuildVaFallbackOutputOtherTasks:
    """BKL-002: sanity checks for other fallback tasks."""

    def test_active_scan_planning_returns_plans(self) -> None:
        bundle = _make_minimal_bundle()
        result = _build_va_fallback_output("active_scan_planning", bundle, {})
        assert "plans" in result
        assert isinstance(result["plans"], list)

    def test_unknown_task_returns_structured_fallback(self) -> None:
        bundle = _make_minimal_bundle()
        result = _build_va_fallback_output("nonexistent_task", bundle, {})
        assert isinstance(result, dict)
        assert "error" in result
        assert result.get("fallback") is True


class TestBuildVaTaskInputIncludesBundle:
    """BKL-002: _build_va_task_input must include bundle for web_scan_planning and generic_web_finding."""

    @pytest.fixture()
    def bundle(self) -> MagicMock:
        b = _make_minimal_bundle()
        return b

    def test_web_scan_planning_input_has_bundle(self, bundle: MagicMock) -> None:
        result = _build_va_task_input(
            "web_scan_planning", bundle, {}, "run_1", "job_1", "eng_1",
        )
        assert "bundle" in result

    def test_generic_web_finding_input_has_bundle(self, bundle: MagicMock) -> None:
        result = _build_va_task_input(
            "generic_web_finding", bundle, {}, "run_1", "job_1", "eng_1",
        )
        assert "bundle" in result

    def test_task_input_has_meta(self, bundle: MagicMock) -> None:
        result = _build_va_task_input(
            "web_scan_planning", bundle, {}, "run_1", "job_1", "eng_1",
        )
        assert "meta" in result
