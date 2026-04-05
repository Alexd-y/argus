"""Test HTTP security headers collector."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from src.recon.recon_http_headers import (
    SecurityHeadersResult,
    _analyze_headers,
    collect_security_headers,
)


@pytest.mark.asyncio
async def test_collect_headers_success() -> None:
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Server": "nginx",
    }

    mock_client = AsyncMock()
    mock_client.get = AsyncMock(return_value=mock_response)
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)

    with patch("src.recon.recon_http_headers.httpx.AsyncClient", return_value=mock_client):
        result = await collect_security_headers("https://example.com")

    assert isinstance(result, SecurityHeadersResult)
    assert result.status_code == 200
    assert result.error is None
    assert len(result.findings) > 0


def test_analyze_headers_all_present() -> None:
    headers = {
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Permissions-Policy": "camera=(), microphone=()",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "X-XSS-Protection": "0",
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
        "X-Permitted-Cross-Domain-Policies": "none",
        "Feature-Policy": "camera 'none'",
    }
    findings, score = _analyze_headers(headers)
    assert score > 50


def test_analyze_headers_none_present() -> None:
    findings, score = _analyze_headers({})
    assert score < 50
    missing = [f for f in findings if not f.present]
    assert len(missing) > 0


def test_server_disclosure() -> None:
    headers = {"Server": "Apache/2.4.41 (Ubuntu)"}
    findings, score = _analyze_headers(headers)
    disclosure = [f for f in findings if f.header == "server" and f.severity == "low"]
    assert len(disclosure) > 0


def test_analyze_returns_header_findings() -> None:
    headers = {"X-Content-Type-Options": "nosniff"}
    findings, score = _analyze_headers(headers)
    present = [f for f in findings if f.present]
    assert any(f.header == "x-content-type-options" and f.compliant for f in present)


@pytest.mark.asyncio
async def test_collect_headers_empty_target() -> None:
    result = await collect_security_headers("")
    assert result.error == "empty_target"
