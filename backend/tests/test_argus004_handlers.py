"""Handler tests for ARGUS-004 — production handlers with mocked tools and LLM.

Tests verify handler structure and integration with tools, NOT mock fallbacks.
"""

from unittest.mock import AsyncMock, patch

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
            patch("src.orchestration.handlers.verify_exploit_poc", return_value=True),
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
