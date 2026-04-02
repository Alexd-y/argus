"""Intelligence API router tests — LLM / Shodan / Perplexity mocked; no real network."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

from starlette.testclient import TestClient

from src.intel.shodan_enricher import ShodanResult, ShodanService
from src.llm.errors import LLMProviderUnavailableError

INTEL_BASE = "/api/v1/intelligence"


class TestAnalyzeTarget:
    """POST /intelligence/analyze-target."""

    def test_returns_503_when_no_llm_provider(self, client: TestClient) -> None:
        with patch(
            "src.api.routers.intelligence.is_llm_available",
            return_value=False,
        ):
            r = client.post(
                f"{INTEL_BASE}/analyze-target",
                json={"target": "https://example.com", "analysis_type": "quick"},
            )
        assert r.status_code == 503
        body = r.json()
        assert body["success"] is False
        assert "LLM service is not configured." in body["detail"]

    def test_returns_503_when_llm_call_fails(self, client: TestClient) -> None:
        with (
            patch(
                "src.api.routers.intelligence.is_llm_available",
                return_value=True,
            ),
            patch(
                "src.api.routers.intelligence.call_llm",
                new_callable=AsyncMock,
                side_effect=LLMProviderUnavailableError("no provider"),
            ),
        ):
            r = client.post(
                f"{INTEL_BASE}/analyze-target",
                json={"target": "10.0.0.1", "analysis_type": "passive"},
            )
        assert r.status_code == 503
        assert r.json()["success"] is False
        assert "LLM analysis is temporarily unavailable." in r.json()["detail"]

    def test_happy_path_json_shape(self, client: TestClient) -> None:
        llm_payload = {
            "attack_surface": ["api.example.com", "443/tcp"],
            "tech_stack": {"web": "nginx", "framework": "unknown"},
            "vuln_categories": ["misconfiguration"],
            "recommended_tools": ["nmap", "nikto"],
            "testing_priority": "high",
            "estimated_time_minutes": 120,
        }
        with (
            patch(
                "src.api.routers.intelligence.is_llm_available",
                return_value=True,
            ),
            patch(
                "src.api.routers.intelligence.call_llm",
                new_callable=AsyncMock,
                return_value=json.dumps(llm_payload),
            ),
        ):
            r = client.post(
                f"{INTEL_BASE}/analyze-target",
                json={"target": "example.com", "analysis_type": "comprehensive"},
            )
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        assert data["attack_surface"] == llm_payload["attack_surface"]
        assert data["tech_stack"] == llm_payload["tech_stack"]
        assert data["vuln_categories"] == llm_payload["vuln_categories"]
        assert data["recommended_tools"] == llm_payload["recommended_tools"]
        assert data["testing_priority"] == "high"
        assert data["estimated_time_minutes"] == 120


class TestShodanEndpoint:
    """GET /intelligence/shodan."""

    def test_returns_503_when_no_shodan_data_mocked(self, client: TestClient) -> None:
        """Simulates missing key / disabled enrichment: enrich_target_host returns None."""
        with patch(
            "src.api.routers.intelligence.enrich_target_host",
            new_callable=AsyncMock,
            return_value=None,
        ):
            r = client.get(f"{INTEL_BASE}/shodan", params={"ip": "8.8.8.8"})
        assert r.status_code == 503
        body = r.json()
        assert body["success"] is False
        assert "Threat intelligence service is temporarily unavailable." in body["detail"]

    def test_happy_path_json_shape(self, client: TestClient) -> None:
        result = ShodanResult(
            ip="8.8.8.8",
            hostnames=["dns.google"],
            org="Google LLC",
            country="US",
            open_ports=[53, 443],
            vulns=["CVE-2020-0001"],
            services=[
                ShodanService(
                    port=443,
                    transport="tcp",
                    product="HTTP",
                    version="2",
                    cpe=["cpe:/a:ietf:tls"],
                )
            ],
        )
        with patch(
            "src.api.routers.intelligence.enrich_target_host",
            new_callable=AsyncMock,
            return_value=result,
        ):
            r = client.get(f"{INTEL_BASE}/shodan", params={"ip": "8.8.8.8"})
        assert r.status_code == 200
        data = r.json()
        assert data["success"] is True
        host = data["host"]
        assert host["ip"] == "8.8.8.8"
        assert host["hostnames"] == ["dns.google"]
        assert host["org"] == "Google LLC"
        assert host["country"] == "US"
        assert host["open_ports"] == [53, 443]
        assert host["vulns"] == ["CVE-2020-0001"]
        assert len(host["services"]) == 1
        assert host["services"][0]["port"] == 443
        assert host["services"][0]["transport"] == "tcp"
        assert host["services"][0]["product"] == "HTTP"
        assert host["services"][0]["version"] == "2"
        assert host["services"][0]["cpe"] == ["cpe:/a:ietf:tls"]


class TestCvePerplexityMocked:
    """POST /intelligence/cve — Perplexity path mocked."""

    def test_returns_503_when_enrich_cve_unavailable(self, client: TestClient) -> None:
        with patch(
            "src.intel.perplexity_enricher.enrich_cve",
            new_callable=AsyncMock,
            return_value=None,
        ):
            r = client.post(
                f"{INTEL_BASE}/cve",
                json={"cve_id": "CVE-2024-1234"},
            )
        assert r.status_code == 503
        assert r.json()["success"] is False
        assert "Threat intelligence service is temporarily unavailable." in r.json()["detail"]

    def test_happy_path_json_shape(self, client: TestClient) -> None:
        intel = MagicMock()
        intel.cve_id = "CVE-2024-1234"
        intel.cvss_v3 = 9.8
        intel.severity = "CRITICAL"
        intel.description = "Test CVE description"
        intel.exploit_available = True
        intel.exploit_sources = ["https://example.com/poc"]
        intel.patch_available = False
        intel.patch_url = None
        intel.actively_exploited = True
        intel.affected_versions = ["1.0", "1.1"]
        intel.remediation = "Upgrade to 2.0"

        with patch(
            "src.intel.perplexity_enricher.enrich_cve",
            new_callable=AsyncMock,
            return_value=intel,
        ):
            r = client.post(
                f"{INTEL_BASE}/cve",
                json={"cve_id": "CVE-2024-1234", "product": "testapp"},
            )
        assert r.status_code == 200
        d = r.json()
        assert d["success"] is True
        assert d["cve_id"] == "CVE-2024-1234"
        assert d["cvss_v3"] == 9.8
        assert d["severity"] == "CRITICAL"
        assert d["description"] == "Test CVE description"
        assert d["exploit_available"] is True
        assert d["exploit_sources"] == ["https://example.com/poc"]
        assert d["patch_available"] is False
        assert d["actively_exploited"] is True
        assert d["affected_versions"] == ["1.0", "1.1"]
        assert d["remediation"] == "Upgrade to 2.0"
