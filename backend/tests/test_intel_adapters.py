"""Tests for OSINT/Intel adapters — Stage 1 recon data sources."""

import os
from unittest.mock import AsyncMock, patch

import pytest

from src.recon.adapters.intel import (
    CrtShIntelAdapter,
    NvdIntelAdapter,
    RdapIntelAdapter,
    ShodanIntelAdapter,
    get_available_intel_adapters,
)
from src.recon.adapters.intel.base import IntelAdapter, _finding


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
        # Ensure we don't fail when key is missing
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
