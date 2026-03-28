"""Tests for security adapters — Gitleaks, Trivy, Semgrep."""

import asyncio

import pytest

from src.recon.adapters.security import (
    GitleaksAdapter,
    SearchsploitAdapter,
    SemgrepAdapter,
    TrivyAdapter,
)


@pytest.mark.asyncio
async def test_gitleaks_run_with_raw_output():
    """Gitleaks parses pre-collected JSON and returns SECRET_CANDIDATE findings."""
    adapter = GitleaksAdapter()
    raw = '[{"RuleID":"aws-access-key","File":"test.py","StartLine":1,"Secret":"AKIAIOSFODNN7EXAMPLE"}]'
    findings = await adapter.run(".", {"raw_output": raw})
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "secret_candidate"
    assert "test.py" in findings[0]["value"]
    assert findings[0]["source_tool"] == "gitleaks"


@pytest.mark.asyncio
async def test_trivy_run_with_raw_output():
    """Trivy parses pre-collected JSON and returns VULNERABILITY findings."""
    adapter = TrivyAdapter()
    raw = '{"Results":[{"Target":"alpine:3.14","Vulnerabilities":[{"VulnerabilityID":"CVE-2021-1234","PkgName":"curl","InstalledVersion":"7.1","Severity":"HIGH"}]}]}'
    findings = await adapter.run("alpine:3.14", {"raw_output": raw})
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "vulnerability"
    assert "CVE-2021-1234" in findings[0]["value"]
    assert findings[0]["source_tool"] == "trivy"


@pytest.mark.asyncio
async def test_searchsploit_run_with_raw_json():
    """Searchsploit parses JSON array and returns findings with CVE in data."""
    adapter = SearchsploitAdapter()
    raw = (
        '[{"Title":"Test Apache","EDB-ID":"12345","Path":"linux/webapps/12345.txt",'
        '"Codes":"CVE-2020-1234"}]'
    )
    findings = await adapter.run("apache", {"raw_output": raw})
    assert len(findings) == 1
    assert findings[0]["source_tool"] == "searchsploit"
    assert "CVE-2020-1234" in (findings[0].get("data") or {}).get("cves", [])


@pytest.mark.asyncio
async def test_semgrep_run_with_raw_output():
    """Semgrep parses pre-collected JSON and returns VULNERABILITY findings."""
    adapter = SemgrepAdapter()
    raw = '{"results":[{"check_id":"python.sql-injection","path":"app.py","start":{"line":10},"extra":{"message":"SQL injection risk","severity":"ERROR"}}]}'
    findings = await adapter.run(".", {"raw_output": raw})
    assert len(findings) == 1
    assert findings[0]["finding_type"] == "vulnerability"
    assert "app.py" in findings[0]["value"]
    assert findings[0]["source_tool"] == "semgrep"


def test_is_available():
    """is_available returns bool (may be False if tool not installed)."""
    for adapter_cls in (GitleaksAdapter, TrivyAdapter, SemgrepAdapter, SearchsploitAdapter):
        adapter = adapter_cls()
        assert isinstance(adapter.is_available(), bool)


def test_run_skips_when_not_available():
    """run returns [] when tool not installed (via _should_skip)."""
    adapter = GitleaksAdapter()
    if not adapter.is_available():
        findings = asyncio.run(adapter.run(".", {}))
        assert findings == []
