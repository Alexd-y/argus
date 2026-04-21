"""Tests for ARGUS-008 ai_prompts — LLM is mandatory, no mock fallbacks."""

import os
from unittest.mock import AsyncMock, patch

import pytest
from src.orchestration.ai_prompts import (
    ai_exploitation,
    ai_post_exploitation,
    ai_recon,
    ai_reporting,
    ai_threat_modeling,
    ai_vuln_analysis,
)
from src.orchestration.phases import (
    ExploitationInput,
    PostExploitationInput,
    ReconInput,
    ReportingInput,
    ThreatModelInput,
    VulnAnalysisInput,
)


class TestAiPromptsWithoutLLM:
    """ai_prompts raise RuntimeError when no LLM configured."""

    @pytest.fixture(autouse=True)
    def clear_llm_keys(self) -> None:
        env_override = {
            "OPENAI_API_KEY": "",
            "DEEPSEEK_API_KEY": "",
            "OPENROUTER_API_KEY": "",
            "GOOGLE_API_KEY": "",
            "KIMI_API_KEY": "",
            "PERPLEXITY_API_KEY": "",
        }
        with patch.dict(os.environ, env_override, clear=False):
            yield

    @pytest.mark.asyncio
    async def test_ai_recon_raises_without_llm(self) -> None:
        with pytest.raises(RuntimeError, match="LLM provider required"):
            await ai_recon(ReconInput(target="https://x.com", options={}))

    @pytest.mark.asyncio
    async def test_ai_threat_modeling_raises_without_llm(self) -> None:
        with pytest.raises(RuntimeError, match="LLM provider required"):
            await ai_threat_modeling(ThreatModelInput(assets=["a1"]))

    @pytest.mark.asyncio
    async def test_ai_vuln_analysis_raises_without_llm(self) -> None:
        with pytest.raises(RuntimeError, match="LLM provider required"):
            await ai_vuln_analysis(VulnAnalysisInput(threat_model={}, assets=[]))

    @pytest.mark.asyncio
    async def test_ai_exploitation_raises_without_llm(self) -> None:
        with pytest.raises(RuntimeError, match="LLM provider required"):
            await ai_exploitation(ExploitationInput(findings=[]))

    @pytest.mark.asyncio
    async def test_ai_post_exploitation_raises_without_llm(self) -> None:
        with pytest.raises(RuntimeError, match="LLM provider required"):
            await ai_post_exploitation(PostExploitationInput(exploits=[]))

    @pytest.mark.asyncio
    async def test_ai_reporting_raises_without_llm(self) -> None:
        with pytest.raises(RuntimeError, match="LLM provider required"):
            await ai_reporting(ReportingInput(target="x.com"))


class TestAiPromptsWithLLM:
    """ai_prompts call LLM when configured and parse JSON."""

    @pytest.mark.asyncio
    async def test_ai_recon_parses_llm_json(self) -> None:
        llm_response = '{"assets": ["svalbard.ca:443 nginx/1.18","93.184.216.34"], "subdomains": ["www.svalbard.ca"], "ports": [80,443]}'
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.orchestration.ai_prompts.call_llm_unified", new_callable=AsyncMock) as m:
                m.return_value = llm_response
                out = await ai_recon(
                    ReconInput(target="https://svalbard.ca", options={}),
                    tool_results="nmap output...",
                )
                assert "svalbard.ca:443 nginx/1.18" in out.assets
                assert "www.svalbard.ca" in out.subdomains
                assert 80 in out.ports
                assert 443 in out.ports

    @pytest.mark.asyncio
    async def test_ai_recon_raises_on_invalid_json(self) -> None:
        """Invalid JSON after retries raises RuntimeError."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.orchestration.ai_prompts.call_llm_unified", new_callable=AsyncMock) as m:
                m.return_value = "not valid json at all"
                with pytest.raises(RuntimeError, match="LLM returned invalid response"):
                    await ai_recon(ReconInput(target="x.com", options={}))

    @pytest.mark.asyncio
    async def test_ai_recon_raises_on_empty_response(self) -> None:
        """Empty LLM response raises RuntimeError."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.orchestration.ai_prompts.call_llm_unified", new_callable=AsyncMock) as m:
                m.return_value = ""
                with pytest.raises(RuntimeError, match="LLM returned invalid response"):
                    await ai_recon(ReconInput(target="x.com", options={}))

    @pytest.mark.asyncio
    async def test_ai_recon_propagates_llm_exception(self) -> None:
        """When call_llm raises, exception propagates (no mock fallback)."""
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.orchestration.ai_prompts.call_llm_unified", new_callable=AsyncMock) as m:
                m.side_effect = RuntimeError("All LLM providers failed")
                with pytest.raises(RuntimeError, match="All LLM providers failed"):
                    await ai_recon(ReconInput(target="x.com", options={}))

    @pytest.mark.asyncio
    async def test_ai_threat_modeling_raises_on_malformed_json(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.orchestration.ai_prompts.call_llm_unified", new_callable=AsyncMock) as m:
                m.return_value = "not json at all"
                with pytest.raises(RuntimeError, match="LLM returned invalid response"):
                    await ai_threat_modeling(ThreatModelInput(assets=["a1"]))

    @pytest.mark.asyncio
    async def test_ai_vuln_analysis_propagates_llm_exception(self) -> None:
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.orchestration.ai_prompts.call_llm_unified", new_callable=AsyncMock) as m:
                m.side_effect = RuntimeError("Rate limit exceeded")
                with pytest.raises(RuntimeError, match="Rate limit exceeded"):
                    await ai_vuln_analysis(VulnAnalysisInput(threat_model={}, assets=[]))

    @pytest.mark.asyncio
    async def test_ai_threat_modeling_parses_valid_json(self) -> None:
        llm_response = '{"threat_model": {"threats": ["SSH brute force"], "attack_surface": ["22/tcp ssh"], "cves": ["CVE-2023-12345"]}}'
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.orchestration.ai_prompts.call_llm_unified", new_callable=AsyncMock) as m:
                m.return_value = llm_response
                out = await ai_threat_modeling(
                    ThreatModelInput(assets=["22/tcp ssh OpenSSH 8.4"]),
                    nvd_data="[]",
                )
                assert "SSH brute force" in out.threat_model["threats"]

    @pytest.mark.asyncio
    async def test_ai_exploitation_parses_valid_json(self) -> None:
        llm_response = '{"exploits": [{"finding_id": "f1", "status": "theoretical", "title": "SSH Key Bruteforce"}], "evidence": []}'
        with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}):
            with patch("src.orchestration.ai_prompts.call_llm_unified", new_callable=AsyncMock) as m:
                m.return_value = llm_response
                out = await ai_exploitation(ExploitationInput(findings=[{"id": "f1"}]))
                assert out.exploits[0]["status"] == "theoretical"
