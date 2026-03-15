"""Phase enum and Pydantic contracts for ARGUS-004 (Scan State Machine).

ScanPhase values, input/output model validation.
"""

import pytest
from pydantic import ValidationError
from src.orchestration.phases import (
    ExploitationInput,
    ExploitationOutput,
    PHASE_ORDER,
    PHASE_PROGRESS,
    PhaseDefinition,
    PostExploitationInput,
    PostExploitationOutput,
    ReconInput,
    ReconOutput,
    ReportingInput,
    ReportingOutput,
    ScanPhase,
    ThreatModelInput,
    ThreatModelOutput,
    VulnAnalysisInput,
    VulnAnalysisOutput,
    get_phase_definition,
)


class TestScanPhase:
    """ScanPhase enum."""

    def test_all_six_phases_exist(self) -> None:
        """All 6 phases defined."""
        phases = list(ScanPhase)
        assert len(phases) == 6

    def test_phase_values(self) -> None:
        """Phase string values match expected."""
        assert ScanPhase.RECON.value == "recon"
        assert ScanPhase.THREAT_MODELING.value == "threat_modeling"
        assert ScanPhase.VULN_ANALYSIS.value == "vuln_analysis"
        assert ScanPhase.EXPLOITATION.value == "exploitation"
        assert ScanPhase.POST_EXPLOITATION.value == "post_exploitation"
        assert ScanPhase.REPORTING.value == "reporting"

    def test_phase_is_str_enum(self) -> None:
        """ScanPhase inherits from str."""
        assert isinstance(ScanPhase.RECON, str)


class TestReconInput:
    """ReconInput schema."""

    def test_minimal_valid(self) -> None:
        """target required, options defaults to empty dict."""
        inp = ReconInput(target="https://example.com")
        assert inp.target == "https://example.com"
        assert inp.options == {}

    def test_with_options(self) -> None:
        """options dict accepted."""
        inp = ReconInput(target="x.com", options={"depth": 5})
        assert inp.options == {"depth": 5}

    def test_missing_target_raises(self) -> None:
        """Missing target raises ValidationError."""
        with pytest.raises(ValidationError):
            ReconInput()


class TestReconOutput:
    """ReconOutput schema."""

    def test_defaults(self) -> None:
        """Default empty lists."""
        out = ReconOutput()
        assert out.assets == []
        assert out.subdomains == []
        assert out.ports == []

    def test_with_data(self) -> None:
        """Valid data passes."""
        out = ReconOutput(
            assets=["a1", "a2"],
            subdomains=["sub.example.com"],
            ports=[80, 443],
        )
        assert out.assets == ["a1", "a2"]
        assert out.ports == [80, 443]


class TestThreatModelInput:
    """ThreatModelInput schema."""

    def test_defaults(self) -> None:
        """assets defaults to empty list."""
        inp = ThreatModelInput()
        assert inp.assets == []

    def test_with_assets(self) -> None:
        """assets list accepted."""
        inp = ThreatModelInput(assets=["a1", "a2"])
        assert inp.assets == ["a1", "a2"]


class TestThreatModelOutput:
    """ThreatModelOutput schema."""

    def test_defaults(self) -> None:
        """threat_model defaults to empty dict."""
        out = ThreatModelOutput()
        assert out.threat_model == {}

    def test_with_data(self) -> None:
        """threat_model dict accepted."""
        out = ThreatModelOutput(threat_model={"threats": ["t1"]})
        assert out.threat_model == {"threats": ["t1"]}


class TestVulnAnalysisInput:
    """VulnAnalysisInput schema."""

    def test_defaults(self) -> None:
        """threat_model and assets default."""
        inp = VulnAnalysisInput()
        assert inp.threat_model == {}
        assert inp.assets == []

    def test_with_data(self) -> None:
        """Both fields accepted."""
        inp = VulnAnalysisInput(
            threat_model={"x": 1},
            assets=["a1"],
        )
        assert inp.threat_model == {"x": 1}
        assert inp.assets == ["a1"]


class TestVulnAnalysisOutput:
    """VulnAnalysisOutput schema."""

    def test_defaults(self) -> None:
        """findings defaults to empty list."""
        out = VulnAnalysisOutput()
        assert out.findings == []

    def test_with_findings(self) -> None:
        """findings list accepted."""
        out = VulnAnalysisOutput(
            findings=[{"severity": "high", "title": "XSS"}]
        )
        assert len(out.findings) == 1
        assert out.findings[0]["severity"] == "high"


class TestExploitationInput:
    """ExploitationInput schema."""

    def test_defaults(self) -> None:
        """findings defaults to empty list."""
        inp = ExploitationInput()
        assert inp.findings == []


class TestExploitationOutput:
    """ExploitationOutput schema."""

    def test_defaults(self) -> None:
        """exploits and evidence default to empty lists."""
        out = ExploitationOutput()
        assert out.exploits == []
        assert out.evidence == []

    def test_with_data(self) -> None:
        """Both fields accepted."""
        out = ExploitationOutput(
            exploits=[{"id": "e1"}],
            evidence=[{"type": "screenshot"}],
        )
        assert len(out.exploits) == 1
        assert len(out.evidence) == 1


class TestPostExploitationInput:
    """PostExploitationInput schema."""

    def test_defaults(self) -> None:
        """exploits defaults to empty list."""
        inp = PostExploitationInput()
        assert inp.exploits == []


class TestPostExploitationOutput:
    """PostExploitationOutput schema."""

    def test_defaults(self) -> None:
        """lateral and persistence default to empty lists."""
        out = PostExploitationOutput()
        assert out.lateral == []
        assert out.persistence == []


class TestReportingInput:
    """ReportingInput schema."""

    def test_defaults(self) -> None:
        """target empty, all outputs None."""
        inp = ReportingInput()
        assert inp.target == ""
        assert inp.recon is None
        assert inp.threat_model is None
        assert inp.vuln_analysis is None
        assert inp.exploitation is None
        assert inp.post_exploitation is None

    def test_with_all_outputs(self) -> None:
        """All optional outputs accepted."""
        recon = ReconOutput(assets=["a1"])
        tm = ThreatModelOutput(threat_model={})
        vuln = VulnAnalysisOutput(findings=[])
        expl = ExploitationOutput(exploits=[])
        post = PostExploitationOutput(lateral=[])
        inp = ReportingInput(
            target="x.com",
            recon=recon,
            threat_model=tm,
            vuln_analysis=vuln,
            exploitation=expl,
            post_exploitation=post,
        )
        assert inp.target == "x.com"
        assert inp.recon is recon


class TestReportingOutput:
    """ReportingOutput schema."""

    def test_defaults(self) -> None:
        """report defaults to empty dict."""
        out = ReportingOutput()
        assert out.report == {}

    def test_with_report(self) -> None:
        """report dict accepted."""
        out = ReportingOutput(report={"summary": {"critical": 1}})
        assert out.report["summary"]["critical"] == 1


class TestPhaseDefinition:
    """PhaseDefinition and PHASE_PROGRESS."""

    def test_phase_progress_mapping(self) -> None:
        """PHASE_PROGRESS has correct values per spec."""
        assert PHASE_PROGRESS["recon"] == 15
        assert PHASE_PROGRESS["threat_modeling"] == 25
        assert PHASE_PROGRESS["vuln_analysis"] == 45
        assert PHASE_PROGRESS["exploitation"] == 65
        assert PHASE_PROGRESS["post_exploitation"] == 85
        assert PHASE_PROGRESS["reporting"] == 100

    def test_get_phase_definition_returns_definition(self) -> None:
        """get_phase_definition returns PhaseDefinition with schemas and keys."""
        pd = get_phase_definition("recon")
        assert isinstance(pd, PhaseDefinition)
        assert pd.name == "recon"
        assert "target" in str(pd.input_schema)
        assert "assets" in str(pd.output_schema)
        assert pd.prompt_key == "recon"
        assert pd.retry_prompt_key == "recon_retry"

    def test_phase_order_matches_scan_phase(self) -> None:
        """PHASE_ORDER has 6 phases in correct sequence."""
        assert len(PHASE_ORDER) == 6
        assert [p.value for p in PHASE_ORDER] == [
            "recon",
            "threat_modeling",
            "vuln_analysis",
            "exploitation",
            "post_exploitation",
            "reporting",
        ]
