"""Handler tests for ARGUS-004 — production handlers with mocked tools and LLM.

Tests verify handler structure and integration with tools, NOT mock fallbacks.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.orchestration.handlers import (
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

_NMAP_OUTPUT = {"success": True, "stdout": "PORT   STATE SERVICE VERSION\n22/tcp open  ssh     OpenSSH 8.4\n80/tcp open  http    nginx 1.18\n443/tcp open  ssl/http nginx 1.18", "stderr": "", "return_code": 0, "execution_time": 5.0}
_DIG_OUTPUT = {"success": True, "stdout": "example.com. 300 IN A 93.184.216.34", "stderr": "", "return_code": 0, "execution_time": 0.5}
_WHOIS_OUTPUT = {"success": True, "stdout": "Domain Name: EXAMPLE.COM\nRegistrar: ICANN", "stderr": "", "return_code": 0, "execution_time": 1.0}


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
            patch("src.orchestration.handlers.ai_threat_modeling", new_callable=AsyncMock) as mock_ai,
        ):
            mock_nvd.return_value.query = AsyncMock(return_value={"vulnerabilities": []})
            mock_ai.return_value = ThreatModelOutput(
                threat_model={"threats": ["SSH brute force"], "attack_surface": ["22/tcp"], "cves": []}
            )
            out = await run_threat_modeling(["22/tcp ssh OpenSSH 8.4", "80/tcp nginx"])
            assert isinstance(out, ThreatModelOutput)
            assert "threats" in out.threat_model
            mock_ai.assert_called_once()


class TestRunVulnAnalysis:
    """run_vuln_analysis handler."""

    @pytest.mark.asyncio
    async def test_returns_findings(self) -> None:
        with patch("src.orchestration.handlers.ai_vuln_analysis", new_callable=AsyncMock) as mock_ai:
            mock_ai.return_value = VulnAnalysisOutput(
                findings=[{"severity": "high", "title": "nginx CVE", "cwe": "CWE-787"}]
            )
            out = await run_vuln_analysis({"threats": []}, ["80/tcp nginx"])
            assert isinstance(out, VulnAnalysisOutput)
            assert len(out.findings) == 1


class TestRunExploitation:
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
        with patch("src.orchestration.handlers.ai_post_exploitation", new_callable=AsyncMock) as mock_ai:
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
                report={"summary": {"critical": 0, "high": 1}, "sections": ["Scope"], "ai_insights": ["Upgrade nginx"]}
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
    async def test_upload_raw_artifact_uses_recon_phase_with_tenant_and_scan(self) -> None:
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
            patch("src.orchestration.ai_prompts.call_llm", new_callable=AsyncMock) as mock_llm,
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
            patch("src.orchestration.handlers.ai_post_exploitation", new_callable=AsyncMock) as mock_ai,
        ):
            mock_ai.return_value = PostExploitationOutput(lateral=[], persistence=[])
            await run_post_exploitation([{"id": "e1"}], tenant_id=None, scan_id="s1")
            mock_upload.assert_not_called()
            await run_post_exploitation([{"id": "e1"}], tenant_id="t1", scan_id=None)
            mock_upload.assert_not_called()
