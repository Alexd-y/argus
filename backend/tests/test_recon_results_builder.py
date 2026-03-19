"""Tests for recon_results_builder (REC-002)."""

import json
from pathlib import Path

import pytest

from src.recon.reporting.recon_results_builder import build_recon_results


@pytest.fixture
def minimal_recon_dir(tmp_path: Path) -> Path:
    """Minimal recon dir with DNS, WHOIS, http_probe, tech_profile."""
    scope_dir = tmp_path / "00_scope"
    domains_dir = tmp_path / "01_domains"
    dns_dir = tmp_path / "03_dns"
    live_dir = tmp_path / "04_live_hosts"

    scope_dir.mkdir()
    domains_dir.mkdir()
    dns_dir.mkdir()
    live_dir.mkdir()

    (scope_dir / "scope.txt").write_text("Target: example.com\n*.example.com", encoding="utf-8")
    (domains_dir / "whois.txt").write_text(
        "Domain Name: example.com\nRegistrar: Test Registrar\nRegistry Expiry Date: 2025-12-31",
        encoding="utf-8",
    )
    (domains_dir / "ns.txt").write_text(
        "example.com.  nameserver = ns1.example.com.",
        encoding="utf-8",
    )
    (domains_dir / "mx.txt").write_text(
        "example.com.  MX preference = 10, mail exchanger = mail.example.com.",
        encoding="utf-8",
    )
    (dns_dir / "resolved.txt").write_text(
        "www.example.com -> 93.184.216.34\napi.example.com -> 93.184.216.35",
        encoding="utf-8",
    )
    (dns_dir / "cname_map.csv").write_text(
        "host,record_type,value,comment\nwww.example.com,CNAME,cdn.example.com,CDN",
        encoding="utf-8",
        newline="",
    )
    (live_dir / "http_probe.csv").write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.com,https://example.com/,https,200,Example,nginx,\n"
        "www.example.com,https://www.example.com/,https,200,WWW,nginx,",
        encoding="utf-8",
        newline="",
    )
    (tmp_path / "tech_profile.csv").write_text(
        "indicator_type,value,evidence,confidence\n"
        "platform,nginx,Server header on https://example.com/,high",
        encoding="utf-8",
        newline="",
    )

    return tmp_path


def test_build_recon_results_returns_valid_schema(minimal_recon_dir: Path) -> None:
    """build_recon_results returns ReconResults validated against schema."""
    result = build_recon_results(minimal_recon_dir, "test-scan-001")

    assert result.target_domain == "example.com"
    assert result.scan_id == "test-scan-001"
    assert result.generated_at is not None

    assert "example.com" in result.dns
    assert "NS" in result.dns["example.com"]
    assert any("ns1.example.com" in v for v in result.dns["example.com"]["NS"])
    assert "MX" in result.dns["example.com"]
    assert any("mail.example.com" in v for v in result.dns["example.com"]["MX"])

    assert "www.example.com" in result.dns
    assert "A" in result.dns["www.example.com"]
    assert "93.184.216.34" in result.dns["www.example.com"]["A"]
    assert "CNAME" in result.dns["www.example.com"]
    assert "cdn.example.com" in result.dns["www.example.com"]["CNAME"]

    assert result.whois
    assert result.whois.get("registrar") == "Test Registrar"

    assert len(result.tech_stack) >= 1
    assert any(t.indicator_type == "platform" for t in result.tech_stack)


def test_build_recon_results_empty_dir(tmp_path: Path) -> None:
    """build_recon_results handles empty recon dir without exception."""
    (tmp_path / "00_scope").mkdir()
    result = build_recon_results(tmp_path, "empty-scan")
    assert result.target_domain in ("unknown", tmp_path.name)
    assert result.scan_id == "empty-scan"
    assert result.dns == {}
    assert result.whois in ({}, {"raw": "", "registrar": "", "expiry": "", "nameservers": [], "registrant": "", "creation_date": ""})


def test_build_recon_results_serializes_to_json(minimal_recon_dir: Path) -> None:
    """ReconResults can be serialized to JSON for recon_results.json."""
    result = build_recon_results(minimal_recon_dir, "scan-1")
    payload = result.model_dump(mode="json")
    json_str = json.dumps(payload, indent=2, ensure_ascii=False)
    parsed = json.loads(json_str)
    assert parsed["target_domain"] == "example.com"
    assert parsed["scan_id"] == "scan-1"
    assert "dns" in parsed
    assert "whois" in parsed
    assert "tech_stack" in parsed
