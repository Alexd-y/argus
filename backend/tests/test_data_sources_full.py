"""Block 9 — Censys, SecurityTrails, VirusTotal, HIBP: unavailable, 200 parse, 429/error (httpx mock, no network)."""

import os
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from src.data_sources import (
    CensysClient,
    HIBPClient,
    SecurityTrailsClient,
    VirusTotalClient,
)


def _ok_response(status_code: int = 200, **kwargs: object) -> httpx.Response:
    """httpx 0.27+ requires ``request`` on Response for ``raise_for_status``."""
    req = httpx.Request("GET", "https://api.local/block9")
    return httpx.Response(status_code, request=req, **kwargs)


@pytest.mark.asyncio
async def test_censys_unavailable_without_credentials() -> None:
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("CENSYS_API_KEY", None)
        os.environ.pop("CENSYS_API_SECRET", None)
        out = await CensysClient().query()
    assert out == {"available": False, "source": "censys"}


@pytest.mark.asyncio
async def test_censys_200_parses_json_search() -> None:
    with patch.dict(os.environ, {"CENSYS_API_KEY": "id", "CENSYS_API_SECRET": "sec"}):
        with patch("src.data_sources.censys_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            payload = {"result": {"hits": [{"ip": "8.8.8.8"}]}}
            mock_client.post = AsyncMock(return_value=_ok_response(200, json=payload))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await CensysClient().query(query_type="search", q="services.http=80")
    assert out["source"] == "censys"
    assert out["available"] is True
    assert out["data"] == payload


@pytest.mark.asyncio
async def test_censys_429_rate_limited() -> None:
    with patch.dict(os.environ, {"CENSYS_API_KEY": "id", "CENSYS_API_SECRET": "sec"}):
        with patch("src.data_sources.censys_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=_ok_response(429))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await CensysClient().query(query_type="search", q="*")
    assert out.get("rate_limited") is True
    assert out.get("status_code") == 429


@pytest.mark.asyncio
async def test_censys_500_returns_empty_dict() -> None:
    with patch.dict(os.environ, {"CENSYS_API_KEY": "id", "CENSYS_API_SECRET": "sec"}):
        with patch("src.data_sources.censys_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=_ok_response(500))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await CensysClient().query(query_type="search", q="*")
    assert out == {}


@pytest.mark.asyncio
async def test_securitytrails_unavailable_without_key() -> None:
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("SECURITYTRAILS_API_KEY", None)
        out = await SecurityTrailsClient().query(domain="example.com")
    assert out == {"available": False, "source": "securitytrails"}


@pytest.mark.asyncio
async def test_securitytrails_200_parses_json() -> None:
    with patch.dict(os.environ, {"SECURITYTRAILS_API_KEY": "st-key"}):
        with patch("src.data_sources.securitytrails_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            payload = {"hostname": "example.com", "apex_domain": "example.com"}
            mock_client.get = AsyncMock(return_value=_ok_response(200, json=payload))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await SecurityTrailsClient().query(
                query_type="domain", domain="example.com"
            )
    assert out["source"] == "securitytrails"
    assert out["available"] is True
    assert out["data"] == payload


@pytest.mark.asyncio
async def test_securitytrails_429() -> None:
    with patch.dict(os.environ, {"SECURITYTRAILS_API_KEY": "st-key"}):
        with patch("src.data_sources.securitytrails_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_ok_response(429))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await SecurityTrailsClient().query(domain="x.com")
    assert out.get("rate_limited") is True


@pytest.mark.asyncio
async def test_securitytrails_502_error_dict() -> None:
    with patch.dict(os.environ, {"SECURITYTRAILS_API_KEY": "st-key"}):
        with patch("src.data_sources.securitytrails_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_ok_response(502))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await SecurityTrailsClient().query(domain="x.com")
    assert out == {}


@pytest.mark.asyncio
async def test_virustotal_unavailable_without_key() -> None:
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("VIRUSTOTAL_API_KEY", None)
        out = await VirusTotalClient().query(domain="evil.com")
    assert out == {"available": False, "source": "virustotal"}


@pytest.mark.asyncio
async def test_virustotal_200_parses_json_domain() -> None:
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "vt"}):
        with patch("src.data_sources.virustotal_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            payload = {"data": {"id": "example.com", "type": "domain"}}
            mock_client.get = AsyncMock(return_value=_ok_response(200, json=payload))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await VirusTotalClient().query(
                query_type="domain", domain="example.com"
            )
    assert out["data"] == payload
    assert out["available"] is True


@pytest.mark.asyncio
async def test_virustotal_429() -> None:
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "vt"}):
        with patch("src.data_sources.virustotal_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_ok_response(429))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await VirusTotalClient().query(domain="x.com")
    assert out.get("rate_limited") is True


@pytest.mark.asyncio
async def test_virustotal_404_http_error_dict() -> None:
    with patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": "vt"}):
        with patch("src.data_sources.virustotal_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_ok_response(404))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await VirusTotalClient().query(domain="missing.invalid")
    assert out == {}


@pytest.mark.asyncio
async def test_hibp_unavailable_without_key() -> None:
    with patch.dict(os.environ, {}, clear=True):
        os.environ.pop("HIBP_API_KEY", None)
        out = await HIBPClient().query(
            query_type="breachedaccount", account="user@example.com"
        )
    assert out == {"available": False, "source": "hibp"}


@pytest.mark.asyncio
async def test_hibp_breaches_200_json_array() -> None:
    with patch.dict(os.environ, {"HIBP_API_KEY": "hibp"}):
        with patch("src.data_sources.hibp_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            payload = [{"Name": "Adobe"}]
            mock_client.get = AsyncMock(return_value=_ok_response(200, json=payload))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await HIBPClient().query(query_type="breaches")
    assert out["data"] == payload


@pytest.mark.asyncio
async def test_hibp_breachedaccount_404_not_breached() -> None:
    with patch.dict(os.environ, {"HIBP_API_KEY": "hibp"}):
        with patch("src.data_sources.hibp_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_ok_response(404))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await HIBPClient().query(
                query_type="breachedaccount", account="clean@example.com"
            )
    assert out["data"] == []
    assert out.get("not_breached") is True


@pytest.mark.asyncio
async def test_hibp_429() -> None:
    with patch.dict(os.environ, {"HIBP_API_KEY": "hibp"}):
        with patch("src.data_sources.hibp_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_ok_response(429))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await HIBPClient().query(query_type="breaches")
    assert out.get("rate_limited") is True


@pytest.mark.asyncio
async def test_hibp_401_error_dict() -> None:
    with patch.dict(os.environ, {"HIBP_API_KEY": "hibp"}):
        with patch("src.data_sources.hibp_client.httpx.AsyncClient") as mock_cls:
            mock_client = AsyncMock()
            mock_client.get = AsyncMock(return_value=_ok_response(401))
            mock_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            out = await HIBPClient().query(query_type="breaches")
    assert out == {}
