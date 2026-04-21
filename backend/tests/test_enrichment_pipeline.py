"""Integration tests for src.intel.enrichment_pipeline."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from dataclasses import dataclass, field


# Test fixtures
def _make_finding(**overrides):
    base = {
        "id": "f-001",
        "finding_id": "f-001",
        "severity": "high",
        "title": "SQL Injection in login",
        "description": "Vulnerable to SQLi",
        "cwe": "CWE-89",
        "cvss": 8.5,
        "owasp_category": "A03",
        "confidence": "likely",
        "cve_ids": ["CVE-2024-1234"],
        "affected_url": "https://target.example/login",
    }
    base.update(overrides)
    return base


def _make_shodan_result():
    """Create a mock ShodanResult dataclass."""
    @dataclass
    class MockShodanResult:
        ip: str = "1.2.3.4"
        hostnames: list = field(default_factory=list)
        org: str = "TestOrg"
        isp: str = "TestISP"
        asn: str = "AS12345"
        country: str = "US"
        open_ports: list = field(default_factory=lambda: [80, 443])
        services: list = field(default_factory=list)
        vulns: list = field(default_factory=lambda: ["CVE-2024-1234", "CVE-2024-5678"])
        tags: list = field(default_factory=list)
    return MockShodanResult()


@dataclass
class MockValidationResult:
    finding_id: str = "f-001"
    status: str = "confirmed"
    confidence: str = "high"
    poc_command: str = "curl -s https://target.example/login"
    exploit_public: bool = False
    exploit_sources: list = field(default_factory=list)


@dataclass
class MockPocResult:
    finding_id: str = "f-001"
    poc_code: str = "#!/usr/bin/env python3\nprint('PoC')"
    playwright_script: str | None = None
    generator_model: str = "deepseek-chat"


# ═══ Tests ═══

class TestEnrichmentPipelineAllDisabled:
    """Pipeline with all features disabled should pass through findings unchanged."""

    @pytest.mark.asyncio
    async def test_all_disabled_returns_findings_unchanged(self):
        findings = [_make_finding()]
        env = {
            "SHODAN_ENRICHMENT_ENABLED": "false",
            "ADVERSARIAL_SCORE_ENABLED": "false",
            "PERPLEXITY_INTEL_ENABLED": "false",
            "EXPLOITABILITY_VALIDATION_ENABLED": "false",
            "POC_GENERATION_ENABLED": "false",
        }
        with patch.dict("os.environ", env, clear=False):
            from src.intel.enrichment_pipeline import run_enrichment_pipeline
            result = await run_enrichment_pipeline(findings, target_ip="1.2.3.4")

        assert result["findings"] == findings
        assert result["shodan_result"] is None
        stats = result["stats"]
        assert stats["shodan_enriched"] is False
        assert stats["adversarial_scored"] is False
        assert stats["perplexity_enriched"] is False
        assert stats["validation_run"] is False
        assert stats["pocs_generated"] == 0


class TestShodanEnrichmentStep:
    """Shodan enrichment step tests."""

    @pytest.mark.asyncio
    async def test_shodan_enrichment_with_results(self):
        findings = [_make_finding()]
        shodan_res = _make_shodan_result()
        env = {
            "SHODAN_ENRICHMENT_ENABLED": "true",
            "ADVERSARIAL_SCORE_ENABLED": "false",
            "PERPLEXITY_INTEL_ENABLED": "false",
            "EXPLOITABILITY_VALIDATION_ENABLED": "false",
            "POC_GENERATION_ENABLED": "false",
        }
        with patch.dict("os.environ", env, clear=False), \
             patch("src.intel.shodan_enricher.enrich_target_host", new_callable=AsyncMock, return_value=shodan_res), \
             patch("src.intel.shodan_enricher.cross_reference_findings", return_value=findings) as mock_xref, \
             patch("src.intel.shodan_enricher.create_findings_from_shodan_vulns", return_value=[_make_finding(id="f-shodan-001", title="Shodan CVE")]):
            from src.intel.enrichment_pipeline import run_enrichment_pipeline
            result = await run_enrichment_pipeline(findings, target_ip="1.2.3.4")

        assert result["stats"]["shodan_enriched"] is True
        assert result["shodan_result"] is shodan_res
        assert len(result["findings"]) == 2  # original + shodan-generated

    @pytest.mark.asyncio
    async def test_shodan_skipped_without_target_ip(self):
        findings = [_make_finding()]
        env = {
            "SHODAN_ENRICHMENT_ENABLED": "true",
            "ADVERSARIAL_SCORE_ENABLED": "false",
            "PERPLEXITY_INTEL_ENABLED": "false",
            "EXPLOITABILITY_VALIDATION_ENABLED": "false",
            "POC_GENERATION_ENABLED": "false",
        }
        with patch.dict("os.environ", env, clear=False):
            from src.intel.enrichment_pipeline import run_enrichment_pipeline
            result = await run_enrichment_pipeline(findings, target_ip=None)

        assert result["stats"]["shodan_enriched"] is False

    @pytest.mark.asyncio
    async def test_shodan_error_graceful_degradation(self):
        findings = [_make_finding()]
        env = {
            "SHODAN_ENRICHMENT_ENABLED": "true",
            "ADVERSARIAL_SCORE_ENABLED": "false",
            "PERPLEXITY_INTEL_ENABLED": "false",
            "EXPLOITABILITY_VALIDATION_ENABLED": "false",
            "POC_GENERATION_ENABLED": "false",
        }
        with patch.dict("os.environ", env, clear=False), \
             patch("src.intel.shodan_enricher.enrich_target_host", new_callable=AsyncMock, side_effect=RuntimeError("API down")):
            from src.intel.enrichment_pipeline import run_enrichment_pipeline
            result = await run_enrichment_pipeline(findings, target_ip="1.2.3.4")

        assert result["stats"]["shodan_enriched"] is False
        assert len(result["findings"]) == 1  # original unchanged


class TestAdversarialScoring:
    """Adversarial scoring step tests."""

    @pytest.mark.asyncio
    async def test_scoring_adds_adversarial_score(self):
        findings = [_make_finding()]
        env = {
            "SHODAN_ENRICHMENT_ENABLED": "false",
            "ADVERSARIAL_SCORE_ENABLED": "true",
            "PERPLEXITY_INTEL_ENABLED": "false",
            "EXPLOITABILITY_VALIDATION_ENABLED": "false",
            "POC_GENERATION_ENABLED": "false",
        }
        with patch.dict("os.environ", env, clear=False):
            from src.intel.enrichment_pipeline import run_enrichment_pipeline
            result = await run_enrichment_pipeline(findings)

        assert result["stats"]["adversarial_scored"] is True
        assert "adversarial_score" in result["findings"][0]
        assert isinstance(result["findings"][0]["adversarial_score"], float)


class TestValidationStep:
    """Exploitability validation step tests."""

    @pytest.mark.asyncio
    async def test_validation_sets_status(self):
        findings = [_make_finding()]
        mock_result = MockValidationResult()
        env = {
            "SHODAN_ENRICHMENT_ENABLED": "false",
            "ADVERSARIAL_SCORE_ENABLED": "false",
            "PERPLEXITY_INTEL_ENABLED": "false",
            "EXPLOITABILITY_VALIDATION_ENABLED": "true",
            "POC_GENERATION_ENABLED": "false",
        }
        with patch.dict("os.environ", env, clear=False), \
             patch("src.validation.exploitability.validate_findings_batch", new_callable=AsyncMock, return_value=[mock_result]):
            from src.intel.enrichment_pipeline import run_enrichment_pipeline
            result = await run_enrichment_pipeline(findings)

        assert result["stats"]["validation_run"] is True
        assert result["stats"]["findings_confirmed"] == 1
        assert result["findings"][0]["validation_status"] == "confirmed"


class TestPocGeneration:
    """PoC generation step tests."""

    @pytest.mark.asyncio
    async def test_poc_generated_for_confirmed(self):
        findings = [_make_finding(validation_status="confirmed")]
        mock_poc = MockPocResult()
        env = {
            "SHODAN_ENRICHMENT_ENABLED": "false",
            "ADVERSARIAL_SCORE_ENABLED": "false",
            "PERPLEXITY_INTEL_ENABLED": "false",
            "EXPLOITABILITY_VALIDATION_ENABLED": "false",
            "POC_GENERATION_ENABLED": "true",
        }
        with patch.dict("os.environ", env, clear=False), \
             patch("src.exploit.generator.generate_pocs_batch", new_callable=AsyncMock, return_value=[mock_poc]):
            from src.intel.enrichment_pipeline import run_enrichment_pipeline
            result = await run_enrichment_pipeline(findings)

        assert result["stats"]["pocs_generated"] == 1
        assert "generated_poc" in result["findings"][0].get("proof_of_concept", {})


class TestEnrichmentFullPipeline:
    """Full pipeline integration test."""

    @pytest.mark.asyncio
    async def test_full_pipeline_all_steps(self):
        findings = [_make_finding()]
        shodan_res = _make_shodan_result()
        mock_validation = MockValidationResult()
        mock_poc = MockPocResult()

        env = {
            "SHODAN_ENRICHMENT_ENABLED": "true",
            "ADVERSARIAL_SCORE_ENABLED": "true",
            "PERPLEXITY_INTEL_ENABLED": "false",  # skip to avoid complex mock
            "EXPLOITABILITY_VALIDATION_ENABLED": "true",
            "POC_GENERATION_ENABLED": "true",
        }
        with patch.dict("os.environ", env, clear=False), \
             patch("src.intel.shodan_enricher.enrich_target_host", new_callable=AsyncMock, return_value=shodan_res), \
             patch("src.intel.shodan_enricher.cross_reference_findings", return_value=findings), \
             patch("src.intel.shodan_enricher.create_findings_from_shodan_vulns", return_value=[]), \
             patch("src.validation.exploitability.validate_findings_batch", new_callable=AsyncMock, return_value=[mock_validation]), \
             patch("src.exploit.generator.generate_pocs_batch", new_callable=AsyncMock, return_value=[mock_poc]):
            from src.intel.enrichment_pipeline import run_enrichment_pipeline
            result = await run_enrichment_pipeline(findings, target_ip="1.2.3.4", scan_id="scan-123")

        stats = result["stats"]
        assert stats["shodan_enriched"] is True
        assert stats["adversarial_scored"] is True
        assert stats["validation_run"] is True
