"""INFRA-004: Validate nginx/api.conf for ARGUS infrastructure.

Validates:
- File exists at infra/nginx/conf.d/api.conf
- Contains upstream block
- Contains proxy_pass
- Contains limit_req_zone and limit_req
- Contains CORS headers
- Contains SSL block (commented)
"""

from pathlib import Path

import pytest

ARGUS_ROOT = Path(__file__).resolve().parent.parent
NGINX_API_CONF_PATH = ARGUS_ROOT / "infra" / "nginx" / "conf.d" / "api.conf"


@pytest.fixture(scope="module")
def nginx_content() -> str:
    """Load nginx api.conf content."""
    return NGINX_API_CONF_PATH.read_text(encoding="utf-8")


class TestInfra004NginxApiConfExists:
    """INFRA-004: nginx api.conf file existence."""

    def test_api_conf_exists(self) -> None:
        """infra/nginx/conf.d/api.conf must exist."""
        assert NGINX_API_CONF_PATH.exists(), f"Not found: {NGINX_API_CONF_PATH}"
        assert NGINX_API_CONF_PATH.is_file()


class TestInfra004NginxApiConfContent:
    """INFRA-004: api.conf must contain required nginx directives."""

    def test_contains_upstream(self, nginx_content: str) -> None:
        """Must define upstream block for backend."""
        assert "upstream" in nginx_content, (
            "INFRA-004: api.conf must contain upstream block"
        )

    def test_contains_proxy_pass(self, nginx_content: str) -> None:
        """Must contain proxy_pass for reverse proxy."""
        assert "proxy_pass" in nginx_content, (
            "INFRA-004: api.conf must contain proxy_pass"
        )

    def test_contains_limit_req_zone(self, nginx_content: str) -> None:
        """Must define rate limit zone."""
        assert "limit_req_zone" in nginx_content, (
            "INFRA-004: api.conf must contain limit_req_zone"
        )

    def test_contains_limit_req(self, nginx_content: str) -> None:
        """Must use limit_req in location."""
        assert "limit_req" in nginx_content, (
            "INFRA-004: api.conf must contain limit_req"
        )

    def test_contains_cors_headers(self, nginx_content: str) -> None:
        """Must contain CORS headers (Access-Control-Allow-*)."""
        assert "Access-Control-Allow-Origin" in nginx_content, (
            "INFRA-004: api.conf must contain CORS headers (Access-Control-Allow-Origin)"
        )
        assert "Access-Control-Allow-Methods" in nginx_content
        assert "Access-Control-Allow-Headers" in nginx_content

    def test_contains_ssl_block_commented(self, nginx_content: str) -> None:
        """Must contain SSL server block (commented for optional production use)."""
        # SSL block is typically: listen 443 ssl
        assert "443" in nginx_content and "ssl" in nginx_content, (
            "INFRA-004: api.conf must contain SSL block (listen 443 ssl)"
        )
        # Block should be commented (starts with #)
        lines = nginx_content.splitlines()
        ssl_lines = [l for l in lines if "443" in l and "ssl" in l]
        assert ssl_lines, "INFRA-004: Must have listen 443 ssl"
        # At least the SSL server block opening should be commented
        commented_ssl = any(
            l.strip().startswith("#") and "443" in l and "ssl" in l
            for l in lines
        )
        assert commented_ssl, (
            "INFRA-004: SSL block must be commented (optional for production)"
        )
