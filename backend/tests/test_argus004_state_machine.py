"""State machine tests for ARGUS-004 (Scan State Machine).

PHASE_ORDER, _phase_to_progress, run_scan_state_machine with mocked session.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.orchestration.phases import ScanPhase
from src.orchestration.state_machine import (
    PHASE_ORDER,
    _phase_to_progress,
    run_scan_state_machine,
)


class TestPhaseOrder:
    """PHASE_ORDER constant."""

    def test_order_has_six_phases(self) -> None:
        """PHASE_ORDER contains exactly 6 phases."""
        assert len(PHASE_ORDER) == 6

    def test_order_is_correct_sequence(self) -> None:
        """Phases in correct pipeline order."""
        expected = [
            ScanPhase.RECON,
            ScanPhase.THREAT_MODELING,
            ScanPhase.VULN_ANALYSIS,
            ScanPhase.EXPLOITATION,
            ScanPhase.POST_EXPLOITATION,
            ScanPhase.REPORTING,
        ]
        assert expected == PHASE_ORDER

    def test_recon_first(self) -> None:
        """RECON is first phase."""
        assert PHASE_ORDER[0] == ScanPhase.RECON

    def test_reporting_last(self) -> None:
        """REPORTING is last phase."""
        assert PHASE_ORDER[-1] == ScanPhase.REPORTING


class TestPhaseToProgress:
    """_phase_to_progress helper (recon 15, threat_modeling 25, vuln_analysis 45, exploitation 65, post_exploitation 85, reporting 100)."""

    def test_recon_progress(self) -> None:
        """First phase maps to 15%."""
        assert _phase_to_progress(ScanPhase.RECON) == 15

    def test_reporting_progress(self) -> None:
        """Last phase maps to 100%."""
        assert _phase_to_progress(ScanPhase.REPORTING) == 100

    def test_middle_phase_progress(self) -> None:
        """VULN_ANALYSIS maps to 45%."""
        assert _phase_to_progress(ScanPhase.VULN_ANALYSIS) == 45

    def test_unknown_phase_returns_zero(self) -> None:
        """Phase not in PHASE_PROGRESS returns 0."""
        class FakePhase:
            value = "unknown"
        assert _phase_to_progress(FakePhase()) == 0


class TestRunScanStateMachine:
    """run_scan_state_machine with mocked session and handlers."""

    @pytest.fixture
    def mock_session(self) -> AsyncMock:
        """Async mock session with add, commit, execute, flush."""
        session = AsyncMock()
        session.add = MagicMock()
        session.commit = AsyncMock()
        session.flush = AsyncMock()
        session.execute = AsyncMock(return_value=MagicMock())
        return session

    @pytest.mark.asyncio
    async def test_runs_all_six_phases(
        self,
        mock_session: AsyncMock,
    ) -> None:
        """State machine iterates all 6 phases."""
        import src.orchestration.state_machine as sm
        from src.orchestration.phases import (
            ExploitationOutput,
            PostExploitationOutput,
            ReconOutput,
            ReportingOutput,
            ThreatModelOutput,
            VulnAnalysisOutput,
        )

        with (
            patch.object(sm, "_check_exploitation_approval_required", AsyncMock(return_value=False)),
            patch.object(sm, "run_recon", AsyncMock(return_value=ReconOutput(assets=["93.184.216.34:80 nginx/1.18"], subdomains=["www.example.com"], ports=[80, 443]))),
            patch.object(sm, "run_threat_modeling", AsyncMock(return_value=ThreatModelOutput(threat_model={"threats": ["Outdated nginx"], "attack_surface": ["80/tcp"]}))),
            patch.object(sm, "run_vuln_analysis", AsyncMock(return_value=VulnAnalysisOutput(findings=[{"severity": "high", "title": "nginx CVE"}]))),
            patch.object(sm, "run_exploit_attempt", AsyncMock(return_value=ExploitationOutput(exploits=[], evidence=[]))),
            patch.object(sm, "run_exploit_verify", AsyncMock(return_value=ExploitationOutput(exploits=[], evidence=[]))),
            patch.object(sm, "run_post_exploitation", AsyncMock(return_value=PostExploitationOutput(lateral=[], persistence=[]))),
            patch.object(sm, "run_reporting", AsyncMock(return_value=ReportingOutput(report={"summary": {"high": 1}}))),
        ):
            await run_scan_state_machine(
                mock_session,
                scan_id="00000000-0000-0000-0000-000000000001",
                tenant_id="00000000-0000-0000-0000-000000000001",
                target="https://example.com",
                options={},
            )

        assert mock_session.add.call_count >= 6
        assert mock_session.commit.await_count >= 6

    @pytest.mark.asyncio
    async def test_records_scan_steps(
        self,
        mock_session: AsyncMock,
    ) -> None:
        """State machine adds ScanStep records for each phase."""
        import src.orchestration.state_machine as sm
        from src.orchestration.phases import (
            ExploitationOutput,
            PostExploitationOutput,
            ReconOutput,
            ReportingOutput,
            ThreatModelOutput,
            VulnAnalysisOutput,
        )

        with (
            patch.object(sm, "_check_exploitation_approval_required", AsyncMock(return_value=False)),
            patch.object(sm, "run_recon", AsyncMock(return_value=ReconOutput(assets=[], subdomains=[], ports=[]))),
            patch.object(sm, "run_threat_modeling", AsyncMock(return_value=ThreatModelOutput(threat_model={}))),
            patch.object(sm, "run_vuln_analysis", AsyncMock(return_value=VulnAnalysisOutput(findings=[]))),
            patch.object(sm, "run_exploit_attempt", AsyncMock(return_value=ExploitationOutput(exploits=[], evidence=[]))),
            patch.object(sm, "run_exploit_verify", AsyncMock(return_value=ExploitationOutput(exploits=[], evidence=[]))),
            patch.object(sm, "run_post_exploitation", AsyncMock(return_value=PostExploitationOutput(lateral=[], persistence=[]))),
            patch.object(sm, "run_reporting", AsyncMock(return_value=ReportingOutput(report={}))),
        ):
            await run_scan_state_machine(
                mock_session,
                scan_id="test-scan-id",
                tenant_id="test-tenant-id",
                target="https://target.com",
                options={},
            )

        add_calls = mock_session.add.call_args_list
        step_names = [
            c[0][0].step_name
            for c in add_calls
            if hasattr(c[0][0], "step_name")
        ]
        assert "recon" in step_names
        assert "reporting" in step_names
        assert len(step_names) == 6

    @pytest.mark.asyncio
    async def test_exploit_flow_attempt_then_verify(
        self,
        mock_session: AsyncMock,
    ) -> None:
        """Exploitation phase calls exploit_attempt first, then exploit_verify with its output."""
        import src.orchestration.state_machine as sm
        from src.orchestration.phases import (
            ExploitationOutput,
            PostExploitationOutput,
            ReconOutput,
            ReportingOutput,
            ThreatModelOutput,
            VulnAnalysisOutput,
        )

        attempt_output = ExploitationOutput(
            exploits=[{"finding_id": "f1", "status": "attempted"}],
            evidence=[{"finding_id": "f1", "type": "screenshot"}],
        )
        verify_output = ExploitationOutput(
            exploits=[{"finding_id": "f1", "status": "verified"}],
            evidence=[{"finding_id": "f1", "type": "screenshot"}],
        )
        mock_attempt = AsyncMock(return_value=attempt_output)
        mock_verify = AsyncMock(return_value=verify_output)

        with (
            patch.object(sm, "_check_exploitation_approval_required", AsyncMock(return_value=False)),
            patch.object(sm, "run_recon", AsyncMock(return_value=ReconOutput(assets=["a1"], subdomains=[], ports=[80]))),
            patch.object(sm, "run_threat_modeling", AsyncMock(return_value=ThreatModelOutput(threat_model={}))),
            patch.object(sm, "run_vuln_analysis", AsyncMock(return_value=VulnAnalysisOutput(findings=[{"id": "f1"}]))),
            patch.object(sm, "run_exploit_attempt", mock_attempt),
            patch.object(sm, "run_exploit_verify", mock_verify),
            patch.object(sm, "run_post_exploitation", AsyncMock(return_value=PostExploitationOutput(lateral=[], persistence=[]))),
            patch.object(sm, "run_reporting", AsyncMock(return_value=ReportingOutput(report={}))),
        ):
            await run_scan_state_machine(
                mock_session,
                scan_id="exploit-flow-scan",
                tenant_id="exploit-flow-tenant",
                target="https://target.com",
                options={},
            )
            mock_attempt.assert_called_once()
            mock_verify.assert_called_once_with(attempt_output)

    @pytest.mark.asyncio
    async def test_exploitation_approval_gate_raises(
        self,
        mock_session: AsyncMock,
    ) -> None:
        """When policy requires approval, ExploitationApprovalRequiredError is raised."""
        import src.orchestration.state_machine as sm
        from src.orchestration.phases import (
            ExploitationOutput,
            PostExploitationOutput,
            ReconOutput,
            ReportingOutput,
            ThreatModelOutput,
            VulnAnalysisOutput,
        )
        from src.orchestration.state_machine import ExploitationApprovalRequiredError

        with (
            patch.object(sm, "_check_exploitation_approval_required", AsyncMock(return_value=True)),
            patch.object(sm, "run_recon", AsyncMock(return_value=ReconOutput(assets=["a1"], subdomains=[], ports=[80]))),
            patch.object(sm, "run_threat_modeling", AsyncMock(return_value=ThreatModelOutput(threat_model={}))),
            patch.object(sm, "run_vuln_analysis", AsyncMock(return_value=VulnAnalysisOutput(findings=[{"id": "f1"}]))),
            patch.object(sm, "run_exploit_attempt", AsyncMock()),
            patch.object(sm, "run_exploit_verify", AsyncMock()),
        ):
            with pytest.raises(ExploitationApprovalRequiredError):
                await run_scan_state_machine(
                    mock_session,
                    scan_id="approval-gate-scan",
                    tenant_id="approval-gate-tenant",
                    target="https://target.com",
                    options={},
                )
