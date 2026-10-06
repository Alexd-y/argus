"""Handler tests for ARGUS-004 — production handlers with mocked tools and LLM.

Tests verify handler structure and integration with tools, NOT mock fallbacks.
"""

import asyncio
import time as _time
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.orchestration.handlers import (
    _QUICK_LLM_RESERVE_SECONDS,
    run_exploitation,
    run_post_exploitation,
    run_recon,
    run_reporting,
    run_threat_modeling,
    run_vuln_analysis,
)
from src.orchestration.phases import (
    ExploitationOutput,
    PostExploitationOutput,
    ReconOutput,
    ReportingOutput,
    ThreatModelOutput,
    VulnAnalysisOutput,
)

_RECON_LLM_RESPONSE = '{"assets": ["93.184.216.34:80 nginx/1.18", "93.184.216.34:443 nginx/1.18"], "subdomains": ["www.example.com", "mail.example.com"], "ports": [80, 443, 22]}'
_THREAT_LLM_RESPONSE = '{"threat_model": {"threats": ["Outdated nginx may have known CVEs", "SSH exposed on port 22"], "attack_surface": ["80/tcp http", "443/tcp https", "22/tcp ssh"], "cves": ["CVE-2021-23017"]}}'
_VULN_LLM_RESPONSE = '{"findings": [{"severity": "high", "title": "nginx CVE-2021-23017", "cwe": "CWE-787", "cvss": 7.7, "description": "1-byte memory overwrite in resolver", "affected_asset": "93.184.216.34:80", "remediation": "Upgrade nginx to 1.21+"}]}'
_EXPLOIT_LLM_RESPONSE = '{"exploits": [{"finding_id": "f1", "status": "theoretical", "title": "nginx resolver overflow", "technique": "T1190", "description": "Memory corruption via crafted DNS response", "impact": "Remote code execution", "difficulty": "hard"}], "evidence": [{"type": "cve_reference", "description": "CVE-2021-23017", "finding_id": "f1"}]}'
_POST_EXPLOIT_LLM_RESPONSE = '{"lateral": [{"technique": "Pivot via compromised web server", "description": "Access internal network", "from_exploit": "nginx overflow"}], "persistence": [{"type": "cron_backdoor", "description": "Crontab reverse shell", "risk_level": "high"}]}'
_REPORT_LLM_RESPONSE = '{"report": {"summary": {"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0, "risk_rating": "high"}, "executive_summary": "The target has one high-severity vulnerability.", "sections": ["Scope", "Methodology", "Findings"], "findings_detail": [{"title": "nginx CVE"}], "ai_insights": ["Upgrade nginx immediately"]}}'

_NMAP_OUTPUT = {
    "success": True,
    "stdout": "PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.4\n80/tcp open  http    nginx 1.18\n443/tcp open  ssl/http nginx 1.18",
    "stderr": "",
    "return_code": 0,
    "execution_time": 5.0,
}
_DIG_OUTPUT = {
    "success": True,
    "stdout": "example.com. 300 IN A 93.184.216.34",
    "stderr": "",
    "return_code": 0,
    "execution_time": 0.5,
}
_WHOIS_OUTPUT = {
    "success": True,
    "stdout": "Domain Name: EXAMPLE.COM\nRegistrar: ICANN",
    "stderr": "",
    "return_code": 0,
    "execution_time": 1.0,
}


class TestRunRecon:
    """run_recon handler with mocked tools."""

    @pytest.mark.asyncio
    async def test_returns_recon_output_with_real_tools(self) -> None:
        """Recon runs tools and returns structured LLM output."""
        with (
            patch("src.orchestration.handlers.execute_command", return_value=_NMAP_OUTPUT),
            patch("src.orchestration.handlers.CrtShClient") as mock_crtsh,
            patch("src.orchestration.handlers.ShodanClient") as mock_shodan,
            patch("src.orchestration.handlers.ai_recon", new_callable=AsyncMock) as mock_ai,
        ):
            mock_crtsh.return_value.query = AsyncMock(return_value={"results": []})
            mock_shodan.return_value.is_available.return_value = False
            mock_ai.return_value = ReconOutput(
                assets=["93.184.216.34:80 nginx/1.18"],
                subdomains=["www.example.com"],
                ports=[80, 443, 22],
            )
            out = await run_recon("https://example.com", {})
            assert isinstance(out, ReconOutput)
            assert len(out.assets) >= 1
            assert len(out.ports) >= 1
            mock_ai.assert_called_once()


class TestRunThreatModeling:
    """run_threat_modeling handler."""

    @pytest.mark.asyncio
    async def test_returns_threat_model_with_nvd(self) -> None:
        """Threat modeling queries NVD and feeds to LLM."""
        with (
            patch("src.orchestration.handlers.NVDClient") as mock_nvd,
            patch(
                "src.orchestration.handlers.ai_threat_modeling", new_callable=AsyncMock
            ) as mock_ai,
        ):
            mock_nvd.return_value.query = AsyncMock(return_value={"vulnerabilities": []})
            mock_ai.return_value = ThreatModelOutput(
                threat_model={
                    "threats": ["SSH brute force"],
                    "attack_surface": ["22/tcp"],
                    "cves": [],
                }
            )
            out = await run_threat_modeling(["22/tcp ssh OpenSSH 8.4", "80/tcp nginx"])
            assert isinstance(out, ThreatModelOutput)
            assert "threats" in out.threat_model
            mock_ai.assert_called_once()


class TestRunThreatModelingQuickBudget:
    """QUICK timeout root-cause fix: threat_modeling must bound NVD + LLM to the
    remaining quick wall-clock budget so this single phase cannot blow the quick
    deadline and get the whole scan hard-killed by the outer asyncio.wait_for."""

    @staticmethod
    def _quick_opts(seconds_until_deadline: float) -> dict:
        deadline = datetime.now(UTC) + timedelta(seconds=seconds_until_deadline)
        return {"execution_mode": "quick", "deadline_at": deadline.isoformat()}

    @pytest.mark.asyncio
    async def test_quick_skips_nvd_when_budget_exhausted(self) -> None:
        """With no budget left, NVD enrichment is skipped entirely (never awaited)."""
        from src.orchestration import handlers as H

        with (
            patch.object(H, "_query_nvd_for_technologies", new_callable=AsyncMock) as mock_nvd,
            patch.object(H, "ai_threat_modeling", new_callable=AsyncMock) as mock_ai,
        ):
            mock_ai.return_value = ThreatModelOutput(threat_model={"threats": []})
            out = await run_threat_modeling(["80/tcp nginx"], scan_options=self._quick_opts(0.0))
            assert isinstance(out, ThreatModelOutput)
            mock_nvd.assert_not_called()

    @pytest.mark.asyncio
    async def test_quick_bounds_slow_nvd(self) -> None:
        """A slow NVD query is bounded by the budget and degrades gracefully, fast."""
        from src.orchestration import handlers as H

        async def _slow_nvd(_assets: list[str]) -> str:
            await asyncio.sleep(5.0)
            return "SHOULD NOT APPEAR"

        with (
            patch.object(H, "_query_nvd_for_technologies", side_effect=_slow_nvd),
            patch.object(H, "ai_threat_modeling", new_callable=AsyncMock) as mock_ai,
        ):
            mock_ai.return_value = ThreatModelOutput(threat_model={"threats": []})
            # A tiny NVD window (reserve + 0.2s) → nvd_budget ≈ 0.2s.
            opts = self._quick_opts(_QUICK_LLM_RESERVE_SECONDS + 0.2)
            start = _time.monotonic()
            out = await run_threat_modeling(["80/tcp nginx"], scan_options=opts)
            elapsed = _time.monotonic() - start
            assert isinstance(out, ThreatModelOutput)
            assert elapsed < 2.0  # bounded, not the full 5s NVD sleep
            if mock_ai.call_args is not None:
                assert mock_ai.call_args.kwargs.get("nvd_data") != "SHOULD NOT APPEAR"

    @pytest.mark.asyncio
    async def test_production_mode_does_not_bound_nvd(self) -> None:
        """Non-quick (production) scans keep the full, unbounded NVD enrichment."""
        from src.orchestration import handlers as H

        with (
            patch.object(H, "_query_nvd_for_technologies", new_callable=AsyncMock) as mock_nvd,
            patch.object(H, "ai_threat_modeling", new_callable=AsyncMock) as mock_ai,
        ):
            mock_nvd.return_value = "cve data"
            mock_ai.return_value = ThreatModelOutput(threat_model={"threats": []})
            out = await run_threat_modeling(["80/tcp nginx"], scan_options={})
            assert isinstance(out, ThreatModelOutput)
            mock_nvd.assert_awaited_once()


class TestQuickBoundedLlm:
    """_quick_bounded_llm — shared quick LLM time-bound used by every analysis phase.

    Root cause of the quick-scan timeout: the WRB read timeout (600s default) far
    exceeds the quick wall-clock budget (300s), so one slow LLM call in any phase
    blows the budget. This helper bounds every quick LLM call to the remaining
    budget; production scans stay unbounded.
    """

    @staticmethod
    def _quick_opts(seconds: float) -> dict:
        deadline = datetime.now(UTC) + timedelta(seconds=seconds)
        return {"execution_mode": "quick", "deadline_at": deadline.isoformat()}

    @pytest.mark.asyncio
    async def test_production_awaits_unbounded(self) -> None:
        from src.orchestration.handlers import _quick_bounded_llm

        async def _coro() -> str:
            return "RESULT"

        out = await _quick_bounded_llm(
            lambda: _coro(), scan_options={}, scan_id="s", phase="recon"
        )
        assert out == "RESULT"

    @pytest.mark.asyncio
    async def test_quick_with_budget_awaits(self) -> None:
        from src.orchestration.handlers import _QUICK_LLM_RESERVE_SECONDS, _quick_bounded_llm

        async def _coro() -> str:
            return "OK"

        out = await _quick_bounded_llm(
            lambda: _coro(),
            scan_options=self._quick_opts(_QUICK_LLM_RESERVE_SECONDS + 30),
            scan_id="s",
            phase="recon",
        )
        assert out == "OK"

    @pytest.mark.asyncio
    async def test_quick_budget_exhausted_returns_none_without_invoking(self) -> None:
        from src.orchestration.handlers import _quick_bounded_llm

        created = {"n": 0}

        async def _coro() -> str:
            created["n"] += 1
            return "X"

        out = await _quick_bounded_llm(
            lambda: _coro(), scan_options=self._quick_opts(0.0), scan_id="s", phase="recon"
        )
        assert out is None
        assert created["n"] == 0  # factory never invoked → no orphaned coroutine

    @pytest.mark.asyncio
    async def test_quick_slow_call_times_out_fast(self) -> None:
        from src.orchestration.handlers import _QUICK_LLM_RESERVE_SECONDS, _quick_bounded_llm

        async def _slow() -> str:
            await asyncio.sleep(5.0)
            return "LATE"

        start = _time.monotonic()
        out = await _quick_bounded_llm(
            lambda: _slow(),
            scan_options=self._quick_opts(_QUICK_LLM_RESERVE_SECONDS + 0.2),
            scan_id="s",
            phase="recon",
        )
        elapsed = _time.monotonic() - start
        assert out is None
        assert elapsed < 2.0


class TestRunReconQuickBudget:
    """RECON must bound its LLM call to the quick budget too (the progress=15 timeout)."""

    @staticmethod
    def _quick_opts(seconds: float) -> dict:
        deadline = datetime.now(UTC) + timedelta(seconds=seconds)
        return {"execution_mode": "quick", "deadline_at": deadline.isoformat()}

    @pytest.mark.asyncio
    async def test_quick_bounds_slow_recon_llm(self) -> None:
        from src.orchestration import handlers as H

        async def _slow_ai_recon(*_a: object, **_k: object) -> ReconOutput:
            await asyncio.sleep(5.0)
            return ReconOutput(assets=["should-not-appear"])

        with (
            patch.object(
                H,
                "run_recon_planned_tool_gather",
                new_callable=AsyncMock,
                return_value=({}, [], []),
            ),
            patch.object(H, "ai_recon", side_effect=_slow_ai_recon),
        ):
            opts = self._quick_opts(_QUICK_LLM_RESERVE_SECONDS + 0.2)
            start = _time.monotonic()
            out = await run_recon("https://alleksy.com", opts)
            elapsed = _time.monotonic() - start
            assert isinstance(out, ReconOutput)
            assert elapsed < 2.0  # bounded, not the full 5s LLM sleep
            assert "should-not-appear" not in out.assets  # fell back, LLM output discarded


class TestRunVulnAnalysis:
    """run_vuln_analysis handler."""

    @pytest.mark.asyncio
    async def test_returns_findings(self) -> None:
        with patch(
            "src.orchestration.handlers.ai_vuln_analysis", new_callable=AsyncMock
        ) as mock_ai:
            mock_ai.return_value = VulnAnalysisOutput(
                findings=[{"severity": "high", "title": "nginx CVE", "cwe": "CWE-787"}]
            )
            out = await run_vuln_analysis({"threats": []}, ["80/tcp nginx"])
            assert isinstance(out, VulnAnalysisOutput)
            assert len(out.findings) == 1


class TestArgus004RunExploitation:
    """run_exploitation handler."""

    @pytest.mark.asyncio
    async def test_returns_exploits_after_verify(self) -> None:
        with (
            patch("src.orchestration.handlers.ai_exploitation", new_callable=AsyncMock) as mock_ai,
            patch(
                "src.orchestration.handlers.verify_exploit_poc_async",
                new_callable=AsyncMock,
                return_value=True,
            ),
        ):
            mock_ai.return_value = ExploitationOutput(
                exploits=[{"finding_id": "f1", "status": "theoretical", "title": "test"}],
                evidence=[{"finding_id": "f1", "type": "cve_ref"}],
            )
            out = await run_exploitation([{"id": "f1"}])
            assert isinstance(out, ExploitationOutput)
            for exp in out.exploits:
                assert exp["status"] == "verified"


class TestRunPostExploitation:
    """run_post_exploitation handler."""

    @pytest.mark.asyncio
    async def test_returns_lateral_and_persistence(self) -> None:
        with patch(
            "src.orchestration.handlers.ai_post_exploitation", new_callable=AsyncMock
        ) as mock_ai:
            mock_ai.return_value = PostExploitationOutput(
                lateral=[{"technique": "Pivot"}],
                persistence=[{"type": "cron", "description": "cron backdoor"}],
            )
            out = await run_post_exploitation([{"id": "e1"}])
            assert isinstance(out, PostExploitationOutput)
            assert len(out.persistence) >= 1


class TestRunReporting:
    """run_reporting handler."""

    @pytest.mark.asyncio
    async def test_returns_report_with_all_sections(self) -> None:
        with patch("src.orchestration.handlers.ai_reporting", new_callable=AsyncMock) as mock_ai:
            mock_ai.return_value = ReportingOutput(
                report={
                    "summary": {"critical": 0, "high": 1},
                    "sections": ["Scope"],
                    "ai_insights": ["Upgrade nginx"],
                }
            )
            out = await run_reporting("https://target.com", None, None, None, None, None)
            assert isinstance(out, ReportingOutput)
            assert "summary" in out.report


def _upload_raw_phase(call: MagicMock) -> str:
    """Phase is the 3rd positional arg to upload_raw_artifact."""
    args, kwargs = call
    if "phase" in kwargs:
        return str(kwargs["phase"])
    return str(args[2])


class TestRawPhaseArtifactsRecon:
    """RAW-002: run_recon persists raw artifacts under phase ``recon`` when tenant + scan are set."""

    @staticmethod
    def _assert_all_calls_recon(mock_upload: MagicMock) -> None:
        assert mock_upload.call_count >= 1
        for c in mock_upload.call_args_list:
            assert _upload_raw_phase(c) == "recon"

    @pytest.mark.asyncio
    async def test_upload_raw_artifact_uses_recon_phase_with_tenant_and_scan(
        self,
    ) -> None:
        tenant_id = "00000000-0000-0000-0000-0000000000aa"
        scan_id = "scan-raw-002"
        with (
            patch(
                "src.orchestration.raw_phase_artifacts.upload_raw_artifact",
                return_value="tenant/scan/recon/raw/x.txt",
            ) as mock_upload,
            patch("src.orchestration.handlers.execute_command", return_value=_NMAP_OUTPUT),
            patch("src.orchestration.handlers.CrtShClient") as mock_crtsh,
            patch("src.orchestration.handlers.ShodanClient") as mock_shodan,
            patch("src.orchestration.handlers.ai_recon", new_callable=AsyncMock) as mock_ai,
        ):
            mock_crtsh.return_value.query = AsyncMock(return_value={"results": []})
            mock_shodan.return_value.is_available.return_value = False
            mock_ai.return_value = ReconOutput(assets=["a"], subdomains=[], ports=[80])
            out = await run_recon(
                "https://example.com",
                {},
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
            assert isinstance(out, ReconOutput)
            self._assert_all_calls_recon(mock_upload)
            mock_ai.assert_called_once()
            call_kw = mock_ai.call_args.kwargs
            assert call_kw.get("raw_sink") is not None
            assert call_kw["raw_sink"].phase == "recon"
            assert call_kw["raw_sink"].tenant_id == tenant_id
            assert call_kw["raw_sink"].scan_id == scan_id

    @pytest.mark.asyncio
    async def test_no_raw_upload_without_tenant_or_scan(self) -> None:
        with (
            patch(
                "src.orchestration.raw_phase_artifacts.upload_raw_artifact",
                return_value=None,
            ) as mock_upload,
            patch("src.orchestration.handlers.execute_command", return_value=_NMAP_OUTPUT),
            patch("src.orchestration.handlers.CrtShClient") as mock_crtsh,
            patch("src.orchestration.handlers.ShodanClient") as mock_shodan,
            patch("src.orchestration.handlers.ai_recon", new_callable=AsyncMock) as mock_ai,
        ):
            mock_crtsh.return_value.query = AsyncMock(return_value={"results": []})
            mock_shodan.return_value.is_available.return_value = False
            mock_ai.return_value = ReconOutput(assets=["a"], subdomains=[], ports=[])
            await run_recon("https://example.com", {}, tenant_id=None, scan_id="s1")
            mock_upload.assert_not_called()
            await run_recon("https://example.com", {}, tenant_id="t1", scan_id=None)
            mock_upload.assert_not_called()
            assert mock_ai.call_args_list[-1].kwargs.get("raw_sink") is None


class TestRawPhaseArtifactsPostExploitation:
    """RAW-003: run_post_exploitation uses phase ``post_exploitation`` when tenant + scan are set."""

    @pytest.mark.asyncio
    async def test_upload_raw_artifact_uses_post_exploitation_phase(self) -> None:
        tenant_id = "00000000-0000-0000-0000-0000000000bb"
        scan_id = "scan-raw-003"
        llm_json = '{"lateral": [], "persistence": []}'
        with (
            patch(
                "src.orchestration.raw_phase_artifacts.upload_raw_artifact",
                return_value="tenant/scan/post_exploitation/raw/x.txt",
            ) as mock_upload,
            patch("src.orchestration.ai_prompts.is_llm_available", return_value=True),
            patch(
                "src.orchestration.ai_prompts.call_llm_unified",
                new_callable=AsyncMock,
            ) as mock_llm,
        ):
            mock_llm.return_value = llm_json
            out = await run_post_exploitation(
                [{"id": "e1", "title": "x"}],
                tenant_id=tenant_id,
                scan_id=scan_id,
            )
            assert isinstance(out, PostExploitationOutput)
            assert mock_upload.call_count >= 1
            for c in mock_upload.call_args_list:
                assert _upload_raw_phase(c) == "post_exploitation"
            mock_llm.assert_called()

    @pytest.mark.asyncio
    async def test_no_raw_upload_without_tenant_or_scan(self) -> None:
        with (
            patch(
                "src.orchestration.raw_phase_artifacts.upload_raw_artifact",
                return_value=None,
            ) as mock_upload,
            patch(
                "src.orchestration.handlers.ai_post_exploitation",
                new_callable=AsyncMock,
            ) as mock_ai,
        ):
            mock_ai.return_value = PostExploitationOutput(lateral=[], persistence=[])
            await run_post_exploitation([{"id": "e1"}], tenant_id=None, scan_id="s1")
            mock_upload.assert_not_called()
            await run_post_exploitation([{"id": "e1"}], tenant_id="t1", scan_id=None)
            mock_upload.assert_not_called()
