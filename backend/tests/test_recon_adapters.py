"""Tests for recon tool adapters — subfinder and httpx parsing/normalization."""

import pytest

from src.recon.adapters.subfinder_adapter import SubfinderAdapter
from src.recon.adapters.httpx_adapter import HttpxAdapter
from src.recon.adapters import registry


class TestSubfinderAdapter:
    """Test subfinder adapter output parsing."""

    @pytest.fixture
    def adapter(self):
        return SubfinderAdapter()

    @pytest.mark.asyncio
    async def test_parse_plain_text(self, adapter):
        output = "api.example.com\nwww.example.com\ntest.example.com"
        results = await adapter.parse_output(output)
        assert len(results) == 3
        assert results[0]["subdomain"] == "api.example.com"

    @pytest.mark.asyncio
    async def test_parse_json_lines(self, adapter):
        output = '{"host":"api.example.com","source":"crtsh"}\n{"host":"www.example.com","source":"dnsdumpster"}'
        results = await adapter.parse_output(output)
        assert len(results) == 2
        assert results[0]["source"] == "crtsh"

    @pytest.mark.asyncio
    async def test_normalize_deduplicates(self, adapter):
        output = "api.example.com\nAPI.EXAMPLE.COM\napi.example.com."
        parsed = await adapter.parse_output(output)
        normalized = await adapter.normalize(parsed)
        assert len(normalized) == 1
        assert normalized[0]["value"] == "api.example.com"

    @pytest.mark.asyncio
    async def test_normalize_finding_type(self, adapter):
        output = "sub.example.com"
        parsed = await adapter.parse_output(output)
        normalized = await adapter.normalize(parsed)
        assert normalized[0]["finding_type"] == "subdomain"
        assert normalized[0]["source_tool"] == "subfinder"

    @pytest.mark.asyncio
    async def test_empty_output(self, adapter):
        results = await adapter.parse_output("")
        assert results == []

    @pytest.mark.asyncio
    async def test_build_command(self, adapter):
        cmd = await adapter.build_command("example.com", {})
        assert "subfinder" in cmd
        assert "-d" in cmd
        assert "example.com" in cmd


class TestHttpxAdapter:
    """Test httpx adapter output parsing."""

    @pytest.fixture
    def adapter(self):
        return HttpxAdapter()

    @pytest.mark.asyncio
    async def test_parse_json_lines(self, adapter):
        output = '{"url":"https://example.com","status_code":200,"title":"Example","tech":["Nginx"]}\n{"url":"https://api.example.com","status_code":301}'
        results = await adapter.parse_output(output)
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_normalize_url_finding(self, adapter):
        output = '{"url":"https://example.com","status_code":200,"title":"Test"}'
        parsed = await adapter.parse_output(output)
        normalized = await adapter.normalize(parsed)
        url_findings = [f for f in normalized if f["finding_type"] == "url"]
        assert len(url_findings) >= 1
        assert url_findings[0]["value"] == "https://example.com"

    @pytest.mark.asyncio
    async def test_normalize_tech_finding(self, adapter):
        output = '{"url":"https://example.com","host":"example.com","tech":["React","Nginx"]}'
        parsed = await adapter.parse_output(output)
        normalized = await adapter.normalize(parsed)
        tech_findings = [f for f in normalized if f["finding_type"] == "technology"]
        assert len(tech_findings) >= 2

    @pytest.mark.asyncio
    async def test_empty_output(self, adapter):
        results = await adapter.parse_output("")
        assert results == []


class TestReconAdapterRegistry:
    """Test adapter registry."""

    def test_subfinder_registered(self):
        adapter = registry.get("subfinder")
        assert adapter is not None
        assert adapter.name == "subfinder"

    def test_httpx_registered(self):
        adapter = registry.get("httpx")
        assert adapter is not None

    def test_get_for_stage(self):
        adapters = registry.get_for_stage(2)
        names = [a.name for a in adapters]
        assert "subfinder" in names

    def test_unknown_adapter(self):
        assert registry.get("nonexistent") is None

    def test_list_all(self):
        all_adapters = registry.list_all()
        assert "subfinder" in all_adapters
        assert "httpx" in all_adapters
