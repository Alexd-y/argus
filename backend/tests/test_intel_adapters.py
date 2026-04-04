"""Tests for OSINT/Intel adapters — Stage 1 recon data sources."""

from __future__ import annotations

import os
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from src.recon.adapters.intel import (
    CrtShIntelAdapter,
    NvdIntelAdapter,
    RdapIntelAdapter,
    ShodanIntelAdapter,
    get_available_intel_adapters,
)
from src.recon.adapters.intel.abuseipdb_adapter import AbuseIpDbIntelAdapter
from src.recon.adapters.intel.base import IntelAdapter, _finding
from src.recon.adapters.intel.censys_adapter import CensysIntelAdapter
from src.recon.adapters.intel.exploitdb_adapter import ExploitDbIntelAdapter
from src.recon.adapters.intel.github_adapter import GitHubIntelAdapter
from src.recon.adapters.intel.greynoise_adapter import GreyNoiseIntelAdapter
from src.recon.adapters.intel.otx_adapter import OtxIntelAdapter
from src.recon.adapters.intel.securitytrails_adapter import SecurityTrailsIntelAdapter
from src.recon.adapters.intel.urlscan_adapter import UrlScanIntelAdapter
from src.recon.adapters.intel.virustotal_adapter import VirusTotalIntelAdapter

# Nine Block-5 intel adapters (explicit list; do not rely on registry alone)
NINE_INTEL_ADAPTER_CLASSES: tuple[type[IntelAdapter], ...] = (
    CensysIntelAdapter,
    SecurityTrailsIntelAdapter,
    VirusTotalIntelAdapter,
    OtxIntelAdapter,
    GreyNoiseIntelAdapter,
    AbuseIpDbIntelAdapter,
    UrlScanIntelAdapter,
    GitHubIntelAdapter,
    ExploitDbIntelAdapter,
)

_ENV_STRIP_FOR_KEYED: dict[str, str] = {
    "OTX_API_KEY": "",
    "GREYNOISE_API_KEY": "",
    "ABUSEIPDB_API_KEY": "",
    "URLSCAN_API_KEY": "",
    "CENSYS_API_KEY": "",
    "CENSYS_API_SECRET": "",
    "SECURITYTRAILS_API_KEY": "",
    "VIRUSTOTAL_API_KEY": "",
    "GITHUB_TOKEN": "",
}


class _FakeHttpResponse:
    """Minimal httpx.Response-like object (sync .json())."""

    def __init__(self, status_code: int, body: dict[str, Any] | None = None) -> None:
        self.status_code = status_code
        self._body = body if body is not None else {}

    def json(self) -> dict[str, Any]:
        return self._body


def _async_client_context(get_impl: Callable[..., Any]) -> MagicMock:
    """Build an AsyncClient mock whose __aenter__ returns self with .get = get_impl."""

    instance = MagicMock()
    instance.__aenter__ = AsyncMock(return_value=instance)
    instance.__aexit__ = AsyncMock(return_value=False)
    instance.get = AsyncMock(side_effect=get_impl)
    client_cls = MagicMock(return_value=instance)
    return client_cls


class TestIntelAdapterBase:
    """Test base IntelAdapter and helpers."""

    def test_finding_helper(self):
        f = _finding("subdomain", "test.example.com", {"source": "crtsh"}, "crtsh", 0.9)
        assert f["finding_type"] == "subdomain"
        assert f["value"] == "test.example.com"
        assert f["data"]["source"] == "crtsh"
        assert f["source_tool"] == "crtsh"
        assert f["confidence"] == 0.9


class TestShodanIntelAdapter:
    """Test Shodan intel adapter."""

    @pytest.fixture
    def adapter(self):
        return ShodanIntelAdapter()

    def test_env_key(self, adapter):
        assert adapter.env_key == "SHODAN_API_KEY"

    def test_skipped_when_no_key(self, adapter):
        with patch.dict(os.environ, {}, clear=False):
            if "SHODAN_API_KEY" in os.environ:
                del os.environ["SHODAN_API_KEY"]
        assert not adapter.is_available()
        assert adapter.env_key is not None

    @pytest.mark.asyncio
    async def test_fetch_skipped_when_no_key(self, adapter):
        with patch.dict(os.environ, {"SHODAN_API_KEY": ""}, clear=False):
            result = await adapter.fetch("example.com")
        assert result["skipped"] is True
        assert result["findings"] == []
        assert result["source"] == "shodan"


class TestCrtShIntelAdapter:
    """Test crt.sh intel adapter."""

    @pytest.fixture
    def adapter(self):
        return CrtShIntelAdapter()

    def test_no_env_key(self, adapter):
        assert adapter.env_key is None
        assert adapter.is_available()

    @pytest.mark.asyncio
    async def test_fetch_returns_findings(self, adapter):
        result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["source"] == "crtsh"
        assert "findings" in result
        for f in result["findings"]:
            assert f["finding_type"] == "subdomain"
            assert f["source_tool"] == "crtsh"


class TestRdapIntelAdapter:
    """Test RDAP intel adapter."""

    @pytest.fixture
    def adapter(self):
        return RdapIntelAdapter()

    def test_no_env_key(self, adapter):
        assert adapter.env_key is None
        assert adapter.is_available()

    @pytest.mark.asyncio
    async def test_fetch_invalid_domain(self, adapter):
        result = await adapter.fetch("")
        assert result["skipped"] is False
        assert result["error"] == "Invalid domain"
        assert result["findings"] == []

    @pytest.mark.asyncio
    async def test_fetch_valid_domain(self, adapter):
        result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["source"] == "rdap"
        assert "findings" in result


class TestNvdIntelAdapter:
    """Test NVD intel adapter."""

    @pytest.fixture
    def adapter(self):
        return NvdIntelAdapter()

    def test_no_env_key(self, adapter):
        assert adapter.env_key is None
        assert adapter.is_available()

    @pytest.mark.asyncio
    async def test_fetch_returns_structure(self, adapter):
        result = await adapter.fetch("nginx")
        assert result["skipped"] is False
        assert result["source"] == "nvd"
        assert "findings" in result


class TestGetAvailableIntelAdapters:
    """Test get_available_intel_adapters."""

    def test_returns_only_configured(self):
        adapters = get_available_intel_adapters()
        names = [a.name for a in adapters]
        assert "crtsh" in names
        assert "rdap" in names
        assert "nvd" in names


# --- Block 5: nine intel adapters (no real network) ---


class TestCensysIntelAdapter:
    @pytest.mark.asyncio
    async def test_skipped_when_no_credentials(self):
        adapter = CensysIntelAdapter()
        with patch.dict(os.environ, {"CENSYS_API_KEY": "", "CENSYS_API_SECRET": ""}, clear=False):
            result = await adapter.fetch("example.com")
        assert result["skipped"] is True
        assert result["error"] is None
        assert result["findings"] == []
        assert result["source"] == "censys"

    @pytest.mark.asyncio
    async def test_fetch_success_mocked_query(self):
        adapter = CensysIntelAdapter()
        search_payload = {
            "data": {
                "result": {
                    "hits": [
                        {
                            "ip": "203.0.113.10",
                            "services": [{"port": 443, "service_name": "https"}],
                        }
                    ]
                }
            }
        }
        cert_payload = {"data": {"result": {"hits": []}}}

        async def fake_query(**_kwargs: Any) -> dict[str, Any]:
            calls.append(1)
            if len(calls) == 1:
                return search_payload
            return cert_payload

        calls: list[int] = []
        with patch.dict(
            os.environ,
            {"CENSYS_API_KEY": "id", "CENSYS_API_SECRET": "secret"},
            clear=False,
        ):
            with patch(
                "src.recon.adapters.intel.censys_adapter.CensysClient.query",
                new_callable=AsyncMock,
                side_effect=fake_query,
            ):
                result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["error"] is None
        assert result["source"] == "censys"
        assert any(f["finding_type"] == "ip_address" for f in result["findings"])
        assert any(f["finding_type"] == "service" for f in result["findings"])


class TestSecurityTrailsIntelAdapter:
    @pytest.mark.asyncio
    async def test_skipped_when_no_key(self):
        adapter = SecurityTrailsIntelAdapter()
        with patch.dict(os.environ, {"SECURITYTRAILS_API_KEY": ""}, clear=False):
            result = await adapter.fetch("example.com")
        assert result["skipped"] is True
        assert result["error"] is None
        assert result["findings"] == []
        assert result["source"] == "securitytrails"

    @pytest.mark.asyncio
    async def test_fetch_success_mocked_query(self):
        adapter = SecurityTrailsIntelAdapter()
        subdomains = {"data": {"subdomains": ["www", "api"]}}

        async def fake_query(*_a: Any, **kwargs: Any) -> dict[str, Any]:
            if kwargs.get("type") == "subdomains":
                return subdomains
            return {"data": {}}

        with patch.dict(os.environ, {"SECURITYTRAILS_API_KEY": "k"}, clear=False):
            with patch(
                "src.recon.adapters.intel.securitytrails_adapter.SecurityTrailsClient.query",
                new_callable=AsyncMock,
                side_effect=fake_query,
            ):
                result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["error"] is None
        assert result["source"] == "securitytrails"
        subs = [f for f in result["findings"] if f["finding_type"] == "subdomain"]
        assert len(subs) >= 2


class TestVirusTotalIntelAdapter:
    @pytest.mark.asyncio
    async def test_skipped_when_no_key(self):
        adapter = VirusTotalIntelAdapter()
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": ""}, clear=False):
            result = await adapter.fetch("example.com")
        assert result["skipped"] is True
        assert result["error"] is None
        assert result["findings"] == []
        assert result["source"] == "virustotal"

    @pytest.mark.asyncio
    async def test_fetch_success_mocked_query(self):
        adapter = VirusTotalIntelAdapter()
        vt_body = {
            "data": {
                "data": {
                    "attributes": {
                        "last_dns_records": [{"type": "A", "value": "93.184.216.34"}],
                        "last_analysis_stats": {"malicious": 0, "suspicious": 0},
                        "categories": {},
                    }
                }
            }
        }
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "k"}, clear=False):
            with patch(
                "src.recon.adapters.intel.virustotal_adapter.VirusTotalClient.query",
                new_callable=AsyncMock,
                return_value=vt_body,
            ):
                result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["error"] is None
        assert result["source"] == "virustotal"
        assert any(f["finding_type"] == "dns_record" for f in result["findings"])


class TestOtxIntelAdapter:
    @pytest.mark.asyncio
    async def test_skipped_when_no_key(self):
        adapter = OtxIntelAdapter()
        with patch.dict(os.environ, {"OTX_API_KEY": ""}, clear=False):
            result = await adapter.fetch("example.com")
        assert result["skipped"] is True
        assert result["error"] is None
        assert result["findings"] == []
        assert result["source"] == "otx"

    @pytest.mark.asyncio
    async def test_fetch_success_mocked_httpx(self):
        adapter = OtxIntelAdapter()

        async def do_get(*_a: Any, **_kw: Any) -> _FakeHttpResponse:
            n = len(responses)
            responses.append(1)
            if n == 0:
                return _FakeHttpResponse(200, {"pulse_info": {"count": 2}})
            return _FakeHttpResponse(
                200,
                {
                    "passive_dns": [
                        {"hostname": "www.example.com", "address": "1.1.1.1"},
                    ]
                },
            )

        responses: list[int] = []
        mock_client_cls = _async_client_context(do_get)
        with patch.dict(os.environ, {"OTX_API_KEY": "secret"}, clear=False):
            with patch("src.recon.adapters.intel.otx_adapter.httpx.AsyncClient", mock_client_cls):
                result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["error"] is None
        assert result["source"] == "otx"
        assert len(result["findings"]) >= 1


class TestGreyNoiseIntelAdapter:
    @pytest.mark.asyncio
    async def test_skipped_when_no_key(self):
        adapter = GreyNoiseIntelAdapter()
        with patch.dict(os.environ, {"GREYNOISE_API_KEY": ""}, clear=False):
            result = await adapter.fetch("example.com")
        assert result["skipped"] is True
        assert result["error"] is None
        assert result["findings"] == []
        assert result["source"] == "greynoise"

    @pytest.mark.asyncio
    async def test_fetch_success_mocked_httpx(self):
        adapter = GreyNoiseIntelAdapter()

        async def do_get(*_a: Any, **_kw: Any) -> _FakeHttpResponse:
            return _FakeHttpResponse(
                200,
                {"noise": False, "riot": True, "classification": "benign", "name": "cdn"},
            )

        mock_client_cls = _async_client_context(do_get)
        with patch.dict(os.environ, {"GREYNOISE_API_KEY": "k"}, clear=False):
            with patch("socket.gethostbyname", return_value="93.184.216.34"):
                with patch(
                    "src.recon.adapters.intel.greynoise_adapter.httpx.AsyncClient",
                    mock_client_cls,
                ):
                    result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["error"] is None
        assert result["source"] == "greynoise"
        assert result["findings"] and result["findings"][0]["finding_type"] == "osint_entry"


class TestAbuseIpDbIntelAdapter:
    @pytest.mark.asyncio
    async def test_skipped_when_no_key(self):
        adapter = AbuseIpDbIntelAdapter()
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": ""}, clear=False):
            result = await adapter.fetch("example.com")
        assert result["skipped"] is True
        assert result["error"] is None
        assert result["findings"] == []
        assert result["source"] == "abuseipdb"

    @pytest.mark.asyncio
    async def test_fetch_success_mocked_httpx(self):
        adapter = AbuseIpDbIntelAdapter()

        async def do_get(*_a: Any, **_kw: Any) -> _FakeHttpResponse:
            return _FakeHttpResponse(
                200,
                {"data": {"abuseConfidenceScore": 5, "totalReports": 1, "isp": "x", "countryCode": "US"}},
            )

        mock_client_cls = _async_client_context(do_get)
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "k"}, clear=False):
            with patch("socket.gethostbyname", return_value="93.184.216.34"):
                with patch(
                    "src.recon.adapters.intel.abuseipdb_adapter.httpx.AsyncClient",
                    mock_client_cls,
                ):
                    result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["error"] is None
        assert result["source"] == "abuseipdb"
        assert result["findings"] and "abuseipdb" in result["findings"][0]["value"]


class TestUrlScanIntelAdapter:
    """env_key is None — adapter does not skip; optional URLSCAN_API_KEY only affects headers."""

    @pytest.mark.asyncio
    async def test_runs_without_optional_api_key(self):
        adapter = UrlScanIntelAdapter()
        with patch.dict(os.environ, {"URLSCAN_API_KEY": ""}, clear=False):
            async def do_get(*_a: Any, **_kw: Any) -> _FakeHttpResponse:
                return _FakeHttpResponse(200, {"results": []})

            mock_client_cls = _async_client_context(do_get)
            with patch("src.recon.adapters.intel.urlscan_adapter.httpx.AsyncClient", mock_client_cls):
                result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["error"] is None
        assert result["source"] == "urlscan"

    @pytest.mark.asyncio
    async def test_fetch_success_mocked_httpx(self):
        adapter = UrlScanIntelAdapter()
        body = {
            "results": [
                {
                    "page": {
                        "url": "https://example.com/",
                        "server": "nginx",
                        "ip": "93.184.216.34",
                    }
                }
            ]
        }

        async def do_get(*_a: Any, **_kw: Any) -> _FakeHttpResponse:
            return _FakeHttpResponse(200, body)

        mock_client_cls = _async_client_context(do_get)
        with patch("src.recon.adapters.intel.urlscan_adapter.httpx.AsyncClient", mock_client_cls):
            result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["error"] is None
        assert result["source"] == "urlscan"
        types = {f["finding_type"] for f in result["findings"]}
        assert "url" in types
        assert "ip_address" in types


class TestGitHubIntelAdapter:
    @pytest.mark.asyncio
    async def test_skipped_when_no_token(self):
        adapter = GitHubIntelAdapter()
        with patch.dict(os.environ, {"GITHUB_TOKEN": ""}, clear=False):
            result = await adapter.fetch("example.com")
        assert result["skipped"] is True
        assert result["error"] is None
        assert result["findings"] == []
        assert result["source"] == "github"

    @pytest.mark.asyncio
    async def test_fetch_success_mocked_query(self):
        adapter = GitHubIntelAdapter()
        advisories = [
            {
                "ghsa_id": "GHSA-test",
                "cve_id": "CVE-2099-1",
                "summary": "example.com related advisory",
                "severity": "high",
            }
        ]
        with patch.dict(os.environ, {"GITHUB_TOKEN": "tok"}, clear=False):
            with patch(
                "src.recon.adapters.intel.github_adapter.GitHubClient.query",
                new_callable=AsyncMock,
                return_value=advisories,
            ):
                result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["error"] is None
        assert result["source"] == "github"
        assert result["findings"] and result["findings"][0]["finding_type"] == "vulnerability"


class TestExploitDbIntelAdapter:
    """No API key — never skipped at availability gate."""

    @pytest.mark.asyncio
    async def test_always_available_no_env_key(self):
        adapter = ExploitDbIntelAdapter()
        assert adapter.env_key is None
        assert adapter.is_available() is True

    @pytest.mark.asyncio
    async def test_fetch_success_mocked_httpx(self):
        adapter = ExploitDbIntelAdapter()
        payload = {
            "data": [
                {
                    "id": 12345,
                    "description": "Test exploit",
                    "platform": {"platform": "linux"},
                    "type": {"name": "remote"},
                }
            ]
        }

        async def do_get(*_a: Any, **_kw: Any) -> _FakeHttpResponse:
            return _FakeHttpResponse(200, payload)

        mock_client_cls = _async_client_context(do_get)
        with patch("src.recon.adapters.intel.exploitdb_adapter.httpx.AsyncClient", mock_client_cls):
            result = await adapter.fetch("example.com")
        assert result["skipped"] is False
        assert result["error"] is None
        assert result["source"] == "exploitdb"
        assert any(f["value"] == "EDB-12345" for f in result["findings"])


@contextmanager
def _patch_urlscan_and_exploitdb_httpx():
    """Avoid outbound HTTP for adapters that always run."""

    async def urlscan_get(*_a: Any, **_kw: Any) -> _FakeHttpResponse:
        return _FakeHttpResponse(200, {"results": []})

    async def exploit_get(*_a: Any, **_kw: Any) -> _FakeHttpResponse:
        return _FakeHttpResponse(200, {"data": []})

    with (
        patch(
            "src.recon.adapters.intel.urlscan_adapter.httpx.AsyncClient",
            _async_client_context(urlscan_get),
        ),
        patch(
            "src.recon.adapters.intel.exploitdb_adapter.httpx.AsyncClient",
            _async_client_context(exploit_get),
        ),
    ):
        yield


class TestAllIntelAdaptersContract:
    """Contract: no stub errors; source matches adapter name."""

    @pytest.mark.asyncio
    async def test_no_stub_not_implemented_empty_env(self):
        with patch.dict(os.environ, _ENV_STRIP_FOR_KEYED, clear=False):
            with _patch_urlscan_and_exploitdb_httpx():
                for AdapterClass in NINE_INTEL_ADAPTER_CLASSES:
                    adapter = AdapterClass()
                    result = await adapter.fetch("example.com")
                    err = result.get("error")
                    assert "Stub" not in str(err or ""), f"{adapter.name}: {err!r}"
                    assert result["source"] == adapter.name

    def test_get_available_intel_adapters_import(self):
        adapters = get_available_intel_adapters()
        assert isinstance(adapters, list)
