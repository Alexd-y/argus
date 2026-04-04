"""Tests for ARGUS-008 data source adapters."""

import logging
import os
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from src.data_sources import (
    CensysClient,
    CrtShClient,
    ExploitDBClient,
    GitHubClient,
    HIBPClient,
    NVDClient,
    SecurityTrailsClient,
    ShodanClient,
    VirusTotalClient,
)


class TestCensysClient:
    """CensysClient."""

    def test_is_available_false_when_no_key(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("CENSYS_API_KEY", None)
            os.environ.pop("CENSYS_API_SECRET", None)
            assert CensysClient().is_available() is False

    def test_is_available_false_when_only_api_id(self) -> None:
        with patch.dict(os.environ, {"CENSYS_API_KEY": "id"}, clear=True):
            os.environ.pop("CENSYS_API_SECRET", None)
            assert CensysClient().is_available() is False

    def test_is_available_true_when_id_and_secret_set(self) -> None:
        with patch.dict(
            os.environ,
            {"CENSYS_API_KEY": "id", "CENSYS_API_SECRET": "secret"},
        ):
            assert CensysClient().is_available() is True

    @pytest.mark.asyncio
    async def test_query_returns_empty_when_not_configured(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("CENSYS_API_KEY", None)
            os.environ.pop("CENSYS_API_SECRET", None)
            result = await CensysClient().query()
            assert result == {"available": False, "source": "censys"}

    @pytest.mark.asyncio
    async def test_query_returns_timeout_payload_on_timeout(self) -> None:
        """Timeout — structured error, no exception propagated."""
        with patch.dict(
            os.environ,
            {"CENSYS_API_KEY": "test-key", "CENSYS_API_SECRET": "test-secret"},
        ):
            with patch("src.data_sources.censys_client.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(
                    side_effect=httpx.TimeoutException("Request timed out")
                )
                mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

                result = await CensysClient().query(query_type="hosts", ip="1.1.1.1")
                assert result == {
                    "source": "censys",
                    "available": True,
                    "error": "timeout",
                }

    @pytest.mark.asyncio
    async def test_query_returns_rate_limited_on_429(self) -> None:
        """429 — explicit rate_limited flag."""
        with patch.dict(
            os.environ,
            {"CENSYS_API_KEY": "test-key", "CENSYS_API_SECRET": "test-secret"},
        ):
            with patch("src.data_sources.censys_client.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_resp = httpx.Response(429)
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

                result = await CensysClient().query(query_type="hosts", ip="8.8.8.8")
                assert result == {
                    "source": "censys",
                    "available": True,
                    "rate_limited": True,
                    "status_code": 429,
                }


class TestVirusTotalClient:
    """VirusTotalClient."""

    def test_is_available_false_when_no_key(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("VIRUSTOTAL_API_KEY", None)
            assert VirusTotalClient().is_available() is False

    @pytest.mark.asyncio
    async def test_query_returns_empty_when_not_configured(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("VIRUSTOTAL_API_KEY", None)
            result = await VirusTotalClient().query()
            assert result == {"available": False, "source": "virustotal"}

    @pytest.mark.asyncio
    async def test_query_returns_timeout_payload_on_timeout(self) -> None:
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "vt-key"}):
            with patch("src.data_sources.virustotal_client.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(
                    side_effect=httpx.TimeoutException("Request timed out")
                )
                mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

                result = await VirusTotalClient().query(domain="example.com")
                assert result == {
                    "source": "virustotal",
                    "available": True,
                    "error": "timeout",
                }

    @pytest.mark.asyncio
    async def test_query_returns_rate_limited_on_429(self) -> None:
        with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "vt-key"}):
            with patch("src.data_sources.virustotal_client.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_resp = httpx.Response(429)
                mock_client.get = AsyncMock(return_value=mock_resp)
                mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

                result = await VirusTotalClient().query(domain="example.com")
                assert result == {
                    "source": "virustotal",
                    "available": True,
                    "rate_limited": True,
                    "status_code": 429,
                }


class TestHIBPClient:
    """HIBPClient."""

    def test_is_available_true_when_key_set(self) -> None:
        with patch.dict(os.environ, {"HIBP_API_KEY": "key"}):
            assert HIBPClient().is_available() is True


class TestSecurityTrailsClient:
    """SecurityTrailsClient."""

    def test_is_available_false_when_no_key(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SECURITYTRAILS_API_KEY", None)
            assert SecurityTrailsClient().is_available() is False


class TestNVDClient:
    """NVDClient — public, no key."""

    @pytest.mark.asyncio
    async def test_query_returns_dict(self) -> None:
        with patch("src.data_sources.nvd_client.httpx.AsyncClient") as mock_cls:
            mock_resp = type("Resp", (), {})()
            mock_resp.raise_for_status = lambda: None
            mock_resp.json = lambda: {"vulnerabilities": [], "totalResults": 0}
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await NVDClient().query()
            assert isinstance(result, dict)

    @pytest.mark.asyncio
    async def test_query_returns_empty_on_timeout(self) -> None:
        with patch("src.data_sources.nvd_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(
                side_effect=httpx.TimeoutException("Request timed out")
            )
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await NVDClient().query()
            assert result == {}


class TestExploitDBClient:
    """ExploitDBClient — public search."""

    @pytest.mark.asyncio
    async def test_query_without_keyword_returns_error(self) -> None:
        result = await ExploitDBClient().query()
        assert result.get("results") == []
        assert result.get("error") == "No keyword provided"


class TestShodanClient:
    """ShodanClient."""

    def test_is_available_false_when_no_key(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SHODAN_API_KEY", None)
            assert ShodanClient().is_available() is False

    def test_is_available_true_when_key_set(self) -> None:
        with patch.dict(os.environ, {"SHODAN_API_KEY": "shodan-key"}):
            assert ShodanClient().is_available() is True

    @pytest.mark.asyncio
    async def test_query_returns_empty_when_not_configured(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("SHODAN_API_KEY", None)
            result = await ShodanClient().query()
            assert result == {}


class TestGitHubClient:
    """GitHubClient."""

    def test_is_available_false_when_no_token(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GITHUB_TOKEN", None)
            assert GitHubClient().is_available() is False

    def test_is_available_true_when_token_set(self) -> None:
        with patch.dict(os.environ, {"GITHUB_TOKEN": "ghp-xxx"}):
            assert GitHubClient().is_available() is True

    @pytest.mark.asyncio
    async def test_query_returns_empty_when_not_configured(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("GITHUB_TOKEN", None)
            result = await GitHubClient().query()
            assert result == {}


class TestCrtShClient:
    """CrtShClient — public, no key."""

    def test_is_available_always_true(self) -> None:
        assert CrtShClient().is_available() is True

    @pytest.mark.asyncio
    async def test_query_returns_dict_on_success(self) -> None:
        with patch("src.data_sources.crtsh_client.httpx.AsyncClient") as mock_cls:
            mock_resp = type("Resp", (), {})()
            mock_resp.raise_for_status = lambda: None
            mock_resp.json = lambda: []
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=mock_resp)
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

            result = await CrtShClient().query(params={"q": "example.com"})
            assert isinstance(result, dict)


class TestDataSourceSecurity:
    """Security: no API key leakage when clients fail."""

    @pytest.mark.asyncio
    async def test_censys_no_api_key_leak_on_exception(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """Exception with key in message must not propagate; result is empty dict."""
        secret_key = "censys-secret-key-abc123"
        with patch.dict(
            os.environ,
            {"CENSYS_API_KEY": "id", "CENSYS_API_SECRET": secret_key},
        ):
            with patch("src.data_sources.censys_client.httpx.AsyncClient") as mock_cls:
                mock_client = AsyncMock()
                mock_client.get = AsyncMock(
                    side_effect=ValueError(
                        f"Auth failed for key={secret_key}"
                    )
                )
                mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
                mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)

                with caplog.at_level(logging.DEBUG):
                    result = await CensysClient().query(query_type="hosts", ip="1.1.1.1")

        assert result == {}
        for record in caplog.records:
            assert secret_key not in record.message
