"""Tests for ARGUS-007 Guardrails — IPValidator, DomainValidator, validate_target_for_tool."""

import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from src.tools.guardrails import validate_target_for_tool
from src.tools.guardrails.domain_validator import DomainValidator
from src.tools.guardrails.ip_validator import IPValidator


class TestIPValidator:
    """IPValidator — blocks private and loopback IPs."""

    def test_blocks_10_range(self) -> None:
        assert IPValidator.is_private_or_loopback("10.0.0.1") is True
        assert IPValidator.is_private_or_loopback("10.255.255.255") is True

    def test_blocks_172_16_31_range(self) -> None:
        assert IPValidator.is_private_or_loopback("172.16.0.1") is True
        assert IPValidator.is_private_or_loopback("172.31.255.255") is True

    def test_blocks_192_168_range(self) -> None:
        assert IPValidator.is_private_or_loopback("192.168.1.1") is True
        assert IPValidator.is_private_or_loopback("192.168.0.0") is True

    def test_blocks_127_loopback(self) -> None:
        assert IPValidator.is_private_or_loopback("127.0.0.1") is True
        assert IPValidator.is_private_or_loopback("127.1.2.3") is True

    def test_allows_public_ip(self) -> None:
        assert IPValidator.is_private_or_loopback("8.8.8.8") is False
        assert IPValidator.is_private_or_loopback("1.1.1.1") is False

    def test_extracts_host_from_url(self) -> None:
        assert IPValidator.is_private_or_loopback("https://192.168.1.1/path") is True
        assert IPValidator.is_private_or_loopback("http://10.0.0.1:8080") is True

    def test_empty_or_none_returns_false(self) -> None:
        assert IPValidator.is_private_or_loopback("") is False
        assert IPValidator.is_private_or_loopback(None) is False  # type: ignore[arg-type]

    def test_non_string_returns_false(self) -> None:
        assert IPValidator.is_private_or_loopback(123) is False  # type: ignore[arg-type]


class TestDomainValidator:
    """DomainValidator — blocks localhost, .local."""

    def test_blocks_localhost(self) -> None:
        assert DomainValidator.is_blocked("localhost") is True
        assert DomainValidator.is_blocked("LOCALHOST") is True

    def test_blocks_local_domain(self) -> None:
        assert DomainValidator.is_blocked("host.local") is True
        assert DomainValidator.is_blocked("something.local") is True

    def test_allows_public_domain(self) -> None:
        assert DomainValidator.is_blocked("example.com") is False
        assert DomainValidator.is_blocked("sub.example.com") is False

    def test_extracts_host_from_url(self) -> None:
        assert DomainValidator.is_blocked("https://localhost/path") is True
        assert DomainValidator.is_blocked("http://example.com") is False


class TestValidateTargetForTool:
    """validate_target_for_tool — integration."""

    def test_empty_target_rejected(self) -> None:
        r = validate_target_for_tool("", "nmap")
        assert r["allowed"] is False
        assert "empty" in r["reason"].lower()

    def test_private_ip_rejected(self) -> None:
        r = validate_target_for_tool("192.168.1.1", "nmap")
        assert r["allowed"] is False
        assert "private" in r["reason"].lower() or "loopback" in r["reason"].lower()

    def test_localhost_rejected(self) -> None:
        r = validate_target_for_tool("localhost", "nmap")
        assert r["allowed"] is False
        assert "blocked" in r["reason"].lower() or "local" in r["reason"].lower()

    def test_public_target_allowed(self) -> None:
        r = validate_target_for_tool("8.8.8.8", "nmap")
        assert r["allowed"] is True
        assert r["reason"] == ""

    def test_public_domain_allowed(self) -> None:
        r = validate_target_for_tool("https://example.com", "nuclei")
        assert r["allowed"] is True

    def test_comma_separated_private_rejected(self) -> None:
        r = validate_target_for_tool("example.com,192.168.1.1", "nmap")
        assert r["allowed"] is False

    def test_space_separated_private_rejected(self) -> None:
        r = validate_target_for_tool("8.8.8.8 192.168.1.1", "nmap")
        assert r["allowed"] is False

    def test_whitespace_only_rejected(self) -> None:
        r = validate_target_for_tool("   ", "nmap")
        assert r["allowed"] is False
        assert "empty" in r["reason"].lower()


# ---------------------------------------------------------------------------
# Security: Guardrails bypass attempts
# ---------------------------------------------------------------------------


class TestGuardrailsBypassAttempts:
    """Attempts to bypass IP/domain guardrails — all must be rejected."""

    def test_private_ip_in_url_path_rejected(self) -> None:
        """URL with private IP in path-like format still extracts host."""
        r = validate_target_for_tool("https://192.168.1.1/admin", "nmap")
        assert r["allowed"] is False

    def test_localhost_with_port_rejected(self) -> None:
        r = validate_target_for_tool("localhost:8080", "nmap")
        assert r["allowed"] is False

    def test_localhost_in_url_rejected(self) -> None:
        r = validate_target_for_tool("http://localhost/api", "nuclei")
        assert r["allowed"] is False

    def test_local_domain_with_subdomain_rejected(self) -> None:
        r = validate_target_for_tool("api.service.local", "nmap")
        assert r["allowed"] is False

    def test_127_0_0_1_rejected(self) -> None:
        r = validate_target_for_tool("127.0.0.1", "nmap")
        assert r["allowed"] is False

    def test_0_0_0_0_rejected(self) -> None:
        """0.0.0.0 is blocked by DomainValidator."""
        r = validate_target_for_tool("0.0.0.0", "nmap")
        assert r["allowed"] is False

    def test_ipv6_loopback_rejected(self) -> None:
        """::1 is blocked by DomainValidator."""
        r = validate_target_for_tool("[::1]", "nmap")
        assert r["allowed"] is False

    def test_172_16_boundary_rejected(self) -> None:
        r = validate_target_for_tool("172.16.0.0", "nmap")
        assert r["allowed"] is False

    def test_172_31_boundary_rejected(self) -> None:
        r = validate_target_for_tool("172.31.255.255", "nmap")
        assert r["allowed"] is False


# ---------------------------------------------------------------------------
# Security: Injection in target (command injection, obfuscation)
# ---------------------------------------------------------------------------


class TestTargetInjectionAttempts:
    """Target field injection attempts — validation must not be bypassed."""

    def test_target_with_shell_metacharacters_returns_valid_result(self) -> None:
        """Target like '8.8.8.8; rm -rf /' — validation completes, returns allowed/reason."""
        r = validate_target_for_tool("8.8.8.8; rm -rf /", "nmap")
        assert "allowed" in r and "reason" in r
        assert isinstance(r["allowed"], bool)

    def test_target_with_newline_still_validates(self) -> None:
        r = validate_target_for_tool("192.168.1.1\n8.8.8.8", "nmap")
        assert r["allowed"] is False

    def test_target_private_ip_with_trailing_injection_rejected(self) -> None:
        r = validate_target_for_tool("192.168.1.1 && id", "nmap")
        assert r["allowed"] is False

    def test_target_public_with_leading_private_rejected(self) -> None:
        """First part is validated; 192.168.1.1 in list triggers rejection."""
        r = validate_target_for_tool("192.168.1.1 8.8.8.8", "nmap")
        assert r["allowed"] is False

    def test_target_private_ip_obfuscated_in_url_rejected(self) -> None:
        r = validate_target_for_tool("http://192.168.1.1:80/", "nmap")
        assert r["allowed"] is False

    def test_target_localhost_localdomain_rejected(self) -> None:
        r = validate_target_for_tool("localhost.localdomain", "nmap")
        assert r["allowed"] is False
