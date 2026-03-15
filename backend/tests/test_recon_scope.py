"""Tests for scope validator — domain, IP, CIDR, URL matching."""

import pytest

from src.recon.schemas.scope import ScopeConfig, ScopeRule
from src.recon.scope.validator import ScopeValidator


def _make_validator(*rules: ScopeRule, wildcard: bool = True) -> ScopeValidator:
    config = ScopeConfig(rules=list(rules), wildcard_subdomains=wildcard)
    return ScopeValidator(config)


class TestDomainScoping:
    """Test domain-based scope validation."""

    def test_exact_match(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="domain", pattern="example.com"))
        assert v.is_in_scope("example.com").is_in_scope is True

    def test_subdomain_wildcard(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="domain", pattern="example.com"))
        assert v.is_in_scope("api.example.com").is_in_scope is True

    def test_subdomain_no_wildcard(self):
        v = _make_validator(
            ScopeRule(rule_type="include", value_type="domain", pattern="example.com"),
            wildcard=False,
        )
        assert v.is_in_scope("api.example.com").is_in_scope is False

    def test_different_domain_rejected(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="domain", pattern="example.com"))
        assert v.is_in_scope("evil.com").is_in_scope is False

    def test_exclude_overrides_include(self):
        v = _make_validator(
            ScopeRule(rule_type="include", value_type="domain", pattern="example.com"),
            ScopeRule(rule_type="exclude", value_type="domain", pattern="admin.example.com"),
        )
        assert v.is_in_scope("example.com").is_in_scope is True
        assert v.is_in_scope("admin.example.com").is_in_scope is False
        assert v.is_in_scope("api.example.com").is_in_scope is True

    def test_wildcard_pattern(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="domain", pattern="*.example.com"))
        assert v.is_in_scope("api.example.com").is_in_scope is True
        assert v.is_in_scope("example.com").is_in_scope is True

    def test_case_insensitive(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="domain", pattern="Example.COM"))
        assert v.is_in_scope("EXAMPLE.com").is_in_scope is True

    def test_trailing_dot(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="domain", pattern="example.com"))
        assert v.is_in_scope("example.com.").is_in_scope is True


class TestIpScoping:
    """Test IP and CIDR scope validation."""

    def test_exact_ip(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="ip", pattern="10.0.0.1"))
        assert v.is_in_scope("10.0.0.1", "ip").is_in_scope is True
        assert v.is_in_scope("10.0.0.2", "ip").is_in_scope is False

    def test_cidr_range(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="cidr", pattern="10.0.0.0/24"))
        assert v.is_in_scope("10.0.0.5", "ip").is_in_scope is True
        assert v.is_in_scope("10.0.1.1", "ip").is_in_scope is False

    def test_cidr_exclude(self):
        v = _make_validator(
            ScopeRule(rule_type="include", value_type="cidr", pattern="10.0.0.0/24"),
            ScopeRule(rule_type="exclude", value_type="ip", pattern="10.0.0.100"),
        )
        assert v.is_in_scope("10.0.0.5", "ip").is_in_scope is True
        assert v.is_in_scope("10.0.0.100", "ip").is_in_scope is False


class TestUrlScoping:
    """Test URL scope validation."""

    def test_url_domain_extraction(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="domain", pattern="example.com"))
        result = v.validate_url("https://api.example.com/v1/users")
        assert result.is_in_scope is True

    def test_url_out_of_scope(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="domain", pattern="example.com"))
        result = v.validate_url("https://evil.com/api")
        assert result.is_in_scope is False


class TestBatchFiltering:
    """Test batch filtering."""

    def test_filter_in_scope(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="domain", pattern="example.com"))
        result = v.filter_in_scope(["api.example.com", "evil.com", "test.example.com"])
        assert result == ["api.example.com", "test.example.com"]

    def test_empty_scope_rejects_all(self):
        config = ScopeConfig(rules=[])
        v = ScopeValidator(config)
        assert v.is_in_scope("example.com").is_in_scope is False

    def test_empty_value_rejected(self):
        v = _make_validator(ScopeRule(rule_type="include", value_type="domain", pattern="example.com"))
        assert v.is_in_scope("").is_in_scope is False
