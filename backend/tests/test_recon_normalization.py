"""Tests for normalization pipeline and dedup logic."""

import pytest

from src.recon.normalization.dedup import dedup_key, deduplicate_findings


class TestDedupKey:
    """Test dedup key generation for different finding types."""

    def test_subdomain_key(self):
        key = dedup_key({"finding_type": "subdomain", "value": "api.example.com"})
        assert key == "subdomain:api.example.com"

    def test_subdomain_case_insensitive(self):
        k1 = dedup_key({"finding_type": "subdomain", "value": "API.Example.COM"})
        k2 = dedup_key({"finding_type": "subdomain", "value": "api.example.com"})
        assert k1 == k2

    def test_subdomain_trailing_dot(self):
        k1 = dedup_key({"finding_type": "subdomain", "value": "api.example.com."})
        k2 = dedup_key({"finding_type": "subdomain", "value": "api.example.com"})
        assert k1 == k2

    def test_url_key_normalizes(self):
        k1 = dedup_key({"finding_type": "url", "value": "https://example.com/path?q=1"})
        k2 = dedup_key({"finding_type": "url", "value": "https://example.com/path?q=2"})
        assert k1 == k2  # query params stripped

    def test_service_key(self):
        key = dedup_key({
            "finding_type": "service",
            "value": "x",
            "data": {"ip": "1.2.3.4", "port": 443, "protocol": "tcp"},
        })
        assert "1.2.3.4" in key
        assert "443" in key

    def test_ip_key(self):
        key = dedup_key({"finding_type": "ip_address", "value": "10.0.0.1"})
        assert key == "ip:10.0.0.1"


class TestDeduplication:
    """Test dedup logic with confidence merging."""

    def test_dedup_removes_duplicates(self):
        findings = [
            {"finding_type": "subdomain", "value": "api.example.com", "confidence": 0.8},
            {"finding_type": "subdomain", "value": "api.example.com", "confidence": 0.9},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1
        assert result[0]["confidence"] == 0.9

    def test_dedup_keeps_different(self):
        findings = [
            {"finding_type": "subdomain", "value": "api.example.com"},
            {"finding_type": "subdomain", "value": "www.example.com"},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 2

    def test_empty_input(self):
        assert deduplicate_findings([]) == []
