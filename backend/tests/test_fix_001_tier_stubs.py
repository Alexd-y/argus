"""FIX-001: TIER_STUBS in reporting.py passed to template context."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from src.services.reporting import TIER_STUBS, ReportGenerator


class TestTierStubsDict:
    """TIER_STUBS must contain the three report tiers with expected structure."""

    def test_has_midgard_key(self) -> None:
        assert "midgard" in TIER_STUBS

    def test_has_asgard_key(self) -> None:
        assert "asgard" in TIER_STUBS

    def test_has_valhalla_key(self) -> None:
        assert "valhalla" in TIER_STUBS

    def test_all_tiers_present(self) -> None:
        assert set(TIER_STUBS.keys()) == {"midgard", "asgard", "valhalla"}

    def test_each_tier_has_label(self) -> None:
        for tier, stub in TIER_STUBS.items():
            assert "label" in stub, f"Tier {tier} missing 'label'"
            assert isinstance(stub["label"], str)

    def test_each_tier_has_focus(self) -> None:
        for tier, stub in TIER_STUBS.items():
            assert "focus" in stub, f"Tier {tier} missing 'focus'"

    def test_each_tier_has_active_web_scan(self) -> None:
        for tier, stub in TIER_STUBS.items():
            assert "active_web_scan" in stub, f"Tier {tier} missing 'active_web_scan'"
            assert isinstance(stub["active_web_scan"], bool)


class TestPrepareTemplateContextIncludesTierStubs:
    """prepare_template_context must inject tier_stubs into context."""

    @pytest.fixture()
    def mock_data(self) -> MagicMock:
        data = MagicMock()
        data.tenant_id = "t1"
        data.scan_id = "s1"
        data.scan = None
        data.report = None
        data.findings = []
        data.timeline = []
        data.phase_inputs = []
        data.phase_outputs = []
        data.tool_runs = []
        data.owasp_summary = None
        data.hibp_pwned_password_summary = None
        data.valhalla_context = MagicMock()
        data.valhalla_context.model_dump.return_value = {}
        data.valhalla_context.wstg_coverage = None
        data.valhalla_context.test_limitations = None
        return data

    @patch("src.services.reporting.has_any_llm_key", return_value=False)
    @patch("src.services.reporting.build_owasp_compliance_rows", return_value=[])
    @patch("src.services.reporting.executive_severity_totals_from_finding_rows", return_value={})
    @patch("src.services.reporting.findings_rows_for_jinja", return_value=[])
    def test_context_has_tier_stubs(
        self, _fr, _es, _owasp, _llm, mock_data: MagicMock,
    ) -> None:
        gen = ReportGenerator()
        ctx = gen.prepare_template_context("midgard", mock_data, {})
        assert "tier_stubs" in ctx
        assert ctx["tier_stubs"] is TIER_STUBS

    @patch("src.services.reporting.has_any_llm_key", return_value=False)
    @patch("src.services.reporting.build_owasp_compliance_rows", return_value=[])
    @patch("src.services.reporting.executive_severity_totals_from_finding_rows", return_value={})
    @patch("src.services.reporting.findings_rows_for_jinja", return_value=[])
    def test_context_tier_stubs_is_dict(
        self, _fr, _es, _owasp, _llm, mock_data: MagicMock,
    ) -> None:
        gen = ReportGenerator()
        ctx = gen.prepare_template_context("valhalla", mock_data, {})
        assert isinstance(ctx["tier_stubs"], dict)
        assert "midgard" in ctx["tier_stubs"]
