"""BKL-005: nginx configuration validation (parse test).

Tests:
- api.conf exists and is parseable
- Contains required security headers
- SSE location has correct proxy settings
- Rate limiting is configured
- Auth endpoints have stricter rate limit zone
- Health check endpoint proxies to backend
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ARGUS_ROOT = Path(__file__).resolve().parent.parent.parent
NGINX_API_CONF_PATH = ARGUS_ROOT / "infra" / "nginx" / "conf.d" / "api.conf"


@pytest.fixture(scope="module")
def nginx_content() -> str:
    """Load nginx api.conf content."""
    assert NGINX_API_CONF_PATH.exists(), f"Not found: {NGINX_API_CONF_PATH}"
    return NGINX_API_CONF_PATH.read_text(encoding="utf-8")


class TestNginxApiConfStructure:
    """BKL-005: api.conf must have well-formed nginx directives."""

    def test_file_exists(self) -> None:
        assert NGINX_API_CONF_PATH.exists()
        assert NGINX_API_CONF_PATH.is_file()

    def test_has_upstream_block(self, nginx_content: str) -> None:
        assert "upstream" in nginx_content
        assert re.search(r"upstream\s+\w+\s*\{", nginx_content), (
            "Must have a named upstream block"
        )

    def test_upstream_has_server(self, nginx_content: str) -> None:
        upstream_match = re.search(
            r"upstream\s+\w+\s*\{(.*?)\}", nginx_content, re.DOTALL,
        )
        assert upstream_match, "upstream block not found"
        assert "server" in upstream_match.group(1)

    def test_has_server_block(self, nginx_content: str) -> None:
        assert re.search(r"server\s*\{", nginx_content)

    def test_listen_directive_present(self, nginx_content: str) -> None:
        assert "listen" in nginx_content
        assert re.search(r"listen\s+80", nginx_content)


class TestNginxSecurityHeaders:
    """BKL-005: api.conf must set security headers."""

    def test_x_frame_options(self, nginx_content: str) -> None:
        assert "X-Frame-Options" in nginx_content

    def test_x_content_type_options(self, nginx_content: str) -> None:
        assert "X-Content-Type-Options" in nginx_content
        assert "nosniff" in nginx_content

    def test_referrer_policy(self, nginx_content: str) -> None:
        assert "Referrer-Policy" in nginx_content

    def test_permissions_policy(self, nginx_content: str) -> None:
        assert "Permissions-Policy" in nginx_content


class TestNginxRateLimiting:
    """BKL-005: api.conf must configure rate limiting."""

    def test_has_limit_req_zone(self, nginx_content: str) -> None:
        zones = re.findall(r"limit_req_zone\s+\S+\s+zone=(\w+)", nginx_content)
        assert len(zones) >= 2, "Must have at least 2 rate limit zones (api + auth)"

    def test_api_zone_exists(self, nginx_content: str) -> None:
        assert re.search(r"zone=api:", nginx_content)

    def test_auth_zone_exists(self, nginx_content: str) -> None:
        assert re.search(r"zone=auth:", nginx_content)

    def test_auth_rate_is_stricter(self, nginx_content: str) -> None:
        api_rate = re.search(r"zone=api:\S+\s+rate=(\d+)r/s", nginx_content)
        auth_rate = re.search(r"zone=auth:\S+\s+rate=(\d+)r/s", nginx_content)
        assert api_rate and auth_rate
        assert int(auth_rate.group(1)) < int(api_rate.group(1)), (
            "Auth rate limit must be stricter than API rate limit"
        )


class TestNginxSSESupport:
    """BKL-005: SSE location for scan events must have correct proxy settings."""

    def test_scans_location_exists(self, nginx_content: str) -> None:
        assert re.search(r"location\s+/api/v1/scans/", nginx_content)

    def test_sse_proxy_buffering_off(self, nginx_content: str) -> None:
        assert "proxy_buffering" in nginx_content
        scan_block = _extract_location_block(nginx_content, "/api/v1/scans/")
        if scan_block:
            assert "proxy_buffering" in scan_block
            assert "off" in scan_block

    def test_sse_chunked_off(self, nginx_content: str) -> None:
        scan_block = _extract_location_block(nginx_content, "/api/v1/scans/")
        if scan_block:
            assert "chunked_transfer_encoding" in scan_block

    def test_sse_long_read_timeout(self, nginx_content: str) -> None:
        scan_block = _extract_location_block(nginx_content, "/api/v1/scans/")
        if scan_block:
            timeout_match = re.search(r"proxy_read_timeout\s+(\d+)s", scan_block)
            assert timeout_match, "SSE location must have proxy_read_timeout"
            assert int(timeout_match.group(1)) >= 600, (
                "SSE proxy_read_timeout must be >= 600s for long-lived connections"
            )


class TestNginxCORSHeaders:
    """BKL-005: api.conf must include CORS headers for API routes."""

    def test_cors_origin_header(self, nginx_content: str) -> None:
        assert "Access-Control-Allow-Origin" in nginx_content

    def test_cors_methods_header(self, nginx_content: str) -> None:
        assert "Access-Control-Allow-Methods" in nginx_content

    def test_cors_headers_header(self, nginx_content: str) -> None:
        assert "Access-Control-Allow-Headers" in nginx_content

    def test_cors_options_handling(self, nginx_content: str) -> None:
        assert "OPTIONS" in nginx_content
        assert "return 204" in nginx_content


class TestNginxHealthCheck:
    """BKL-005: health endpoint must proxy to backend."""

    def test_health_location_exists(self, nginx_content: str) -> None:
        assert re.search(r"location\s+/health", nginx_content)

    def test_health_proxies_to_backend(self, nginx_content: str) -> None:
        health_block = _extract_location_block(nginx_content, "/health")
        if health_block:
            assert "proxy_pass" in health_block
            assert "/health" in health_block


def _extract_location_block(content: str, path: str) -> str | None:
    """Extract a location block body from nginx config."""
    pattern = re.escape(path)
    match = re.search(rf"location\s+{pattern}\s*\{{", content)
    if not match:
        return None
    start = match.end()
    depth = 1
    for i in range(start, len(content)):
        if content[i] == "{":
            depth += 1
        elif content[i] == "}":
            depth -= 1
            if depth == 0:
                return content[start:i]
    return None
