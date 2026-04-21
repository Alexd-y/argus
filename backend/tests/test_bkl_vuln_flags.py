"""BKL-001: Validate vulnerability override specs and generic tool IDs.

Tests:
- _VULN_OVERRIDE_SPECS contains csrf_enabled, rce_enabled, idor_enabled entries
- All tool IDs in override specs are consistent with expected patterns
- _GENERIC_TOOL_IDS includes nuclei variant IDs
- plan_tools_by_scan_mode respects vuln override flags
"""

from __future__ import annotations

import pytest

from src.recon.vulnerability_analysis.active_scan.planner import (
    _VULN_OVERRIDE_SPECS,
    plan_tools_by_scan_mode,
)
from src.recon.vulnerability_analysis.active_scan.va_active_scan_phase import (
    _GENERIC_TOOL_IDS,
)


class TestVulnOverrideSpecsPresence:
    """BKL-001: _VULN_OVERRIDE_SPECS must include new vulnerability flag entries."""

    @pytest.mark.parametrize(
        "flag_key",
        ["csrf_enabled", "rce_enabled", "idor_enabled", "xss_enabled", "sqli_enabled", "ssrf_enabled", "lfi_enabled"],
    )
    def test_vuln_override_spec_key_present(self, flag_key: str) -> None:
        assert flag_key in _VULN_OVERRIDE_SPECS, (
            f"_VULN_OVERRIDE_SPECS must have key '{flag_key}'"
        )

    @pytest.mark.parametrize(
        "flag_key",
        ["csrf_enabled", "rce_enabled", "idor_enabled"],
    )
    def test_vuln_override_spec_not_empty(self, flag_key: str) -> None:
        specs = _VULN_OVERRIDE_SPECS[flag_key]
        assert len(specs) > 0, f"Override specs for '{flag_key}' must be non-empty"

    def test_csrf_enabled_has_nuclei_csrf(self) -> None:
        tool_ids = {s.tool_id for s in _VULN_OVERRIDE_SPECS["csrf_enabled"]}
        assert "nuclei_csrf" in tool_ids

    def test_rce_enabled_has_nuclei_rce(self) -> None:
        tool_ids = {s.tool_id for s in _VULN_OVERRIDE_SPECS["rce_enabled"]}
        assert "nuclei_rce" in tool_ids

    def test_rce_enabled_has_commix(self) -> None:
        tool_ids = {s.tool_id for s in _VULN_OVERRIDE_SPECS["rce_enabled"]}
        assert "commix" in tool_ids

    def test_idor_enabled_has_nuclei_idor(self) -> None:
        tool_ids = {s.tool_id for s in _VULN_OVERRIDE_SPECS["idor_enabled"]}
        assert "nuclei_idor" in tool_ids

    def test_all_spec_tool_ids_are_strings(self) -> None:
        for flag_key, specs in _VULN_OVERRIDE_SPECS.items():
            for spec in specs:
                assert isinstance(spec.tool_id, str) and spec.tool_id.strip(), (
                    f"Invalid tool_id in '{flag_key}': {spec.tool_id!r}"
                )

    def test_all_spec_binaries_are_strings(self) -> None:
        for flag_key, specs in _VULN_OVERRIDE_SPECS.items():
            for spec in specs:
                assert isinstance(spec.binary, str) and spec.binary.strip(), (
                    f"Invalid binary in '{flag_key}': {spec.binary!r}"
                )


class TestGenericToolIDs:
    """BKL-001: _GENERIC_TOOL_IDS must include nuclei variants and scan-mode tools."""

    @pytest.mark.parametrize(
        "expected_id",
        [
            "nuclei_sqli",
            "nuclei_ssrf",
            "nuclei_csrf",
            "nuclei_rce",
            "nuclei_idor",
            "curl_cors",
            "corscanner",
            "wafw00f",
            "whatwaf",
            "arjun",
            "ffuf_lfi",
        ],
    )
    def test_generic_tool_id_present(self, expected_id: str) -> None:
        assert expected_id in _GENERIC_TOOL_IDS, (
            f"_GENERIC_TOOL_IDS must contain '{expected_id}'"
        )

    def test_generic_tool_ids_is_frozenset(self) -> None:
        assert isinstance(_GENERIC_TOOL_IDS, frozenset)


class TestPlanToolsByScanModeVulnOverrides:
    """BKL-001: plan_tools_by_scan_mode injects vuln-specific tools when flags are set."""

    @pytest.fixture(autouse=True)
    def _patch_tool_check(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "src.recon.vulnerability_analysis.active_scan.planner.check_tool_available",
            lambda binary, use_sandbox=False: True,
        )

    def test_csrf_enabled_adds_nuclei_csrf(self) -> None:
        steps = plan_tools_by_scan_mode(
            "standard",
            scan_options={"vulnerabilities": {"csrf_enabled": True}},
            target_url="http://example.com/?q=1",
        )
        tool_ids = {s.tool_id for s in steps}
        assert "nuclei_csrf" in tool_ids

    def test_rce_enabled_adds_nuclei_rce(self) -> None:
        steps = plan_tools_by_scan_mode(
            "standard",
            scan_options={"vulnerabilities": {"rce_enabled": True}},
            target_url="http://example.com/?q=1",
        )
        tool_ids = {s.tool_id for s in steps}
        assert "nuclei_rce" in tool_ids

    def test_idor_enabled_adds_nuclei_idor(self) -> None:
        steps = plan_tools_by_scan_mode(
            "standard",
            scan_options={"vulnerabilities": {"idor_enabled": True}},
            target_url="http://example.com/?q=1",
        )
        tool_ids = {s.tool_id for s in steps}
        assert "nuclei_idor" in tool_ids

    def test_empty_target_returns_empty(self) -> None:
        steps = plan_tools_by_scan_mode("deep", target_url="")
        assert steps == []

    def test_no_vuln_flags_standard_returns_baseline(self) -> None:
        steps = plan_tools_by_scan_mode(
            "standard",
            target_url="http://example.com/?q=1",
        )
        assert len(steps) > 0
        for s in steps:
            assert s.url == "http://example.com/?q=1"
