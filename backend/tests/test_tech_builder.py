"""Tests for tech_builder (REC-005: tech_profile.json export)."""

import json
from pathlib import Path

import pytest

from app.schemas.recon.stage1 import TechProfileEntry
from src.recon.reporting.tech_builder import build_tech_profile, build_tech_profile_json


@pytest.fixture
def http_probe_csv(tmp_path: Path) -> Path:
    """Minimal http_probe.csv with nginx and Cloudflare Server headers."""
    path = tmp_path / "http_probe.csv"
    path.write_text(
        "host,url,scheme,status,title,server,redirect\n"
        "example.com,https://example.com/,https,200,Example,nginx,\n"
        "www.example.com,https://www.example.com/,https,200,WWW,Cloudflare,",
        encoding="utf-8",
        newline="",
    )
    return path


def test_build_tech_profile_json_returns_valid_entries(http_probe_csv: Path) -> None:
    """build_tech_profile_json returns list of TechProfileEntry validated against schema."""
    entries = build_tech_profile_json(http_probe_csv)
    assert isinstance(entries, list)
    assert len(entries) >= 2

    for entry in entries:
        assert isinstance(entry, TechProfileEntry)
        assert entry.host
        assert entry.indicator_type
        assert entry.value
        assert entry.evidence is not None
        if entry.confidence is not None:
            assert 0.0 <= entry.confidence <= 1.0


def test_build_tech_profile_json_matches_csv_content(http_probe_csv: Path) -> None:
    """build_tech_profile_json produces same indicators as build_tech_profile CSV."""
    csv_content = build_tech_profile(http_probe_csv)
    entries = build_tech_profile_json(http_probe_csv)

    csv_lines = [l for l in csv_content.strip().splitlines() if l]
    csv_header = csv_lines[0]
    csv_data_rows = csv_lines[1:]

    assert "indicator_type" in csv_header
    assert "value" in csv_header
    assert len(entries) == len(csv_data_rows)

    for i, entry in enumerate(entries):
        assert entry.indicator_type in ("platform", "cdn", "waf")
        assert entry.value
        assert "Server header" in entry.evidence or entry.evidence == "Server header"


def test_build_tech_profile_json_serializable_to_json(http_probe_csv: Path) -> None:
    """Entries can be serialized to valid JSON (tech_profile.json format)."""
    entries = build_tech_profile_json(http_probe_csv)
    dumped = [e.model_dump(mode="json") for e in entries]
    json_str = json.dumps(dumped, indent=2, ensure_ascii=False)

    parsed = json.loads(json_str)
    assert isinstance(parsed, list)
    for item in parsed:
        TechProfileEntry.model_validate(item)


def test_build_tech_profile_json_nonexistent_path_returns_empty(tmp_path: Path) -> None:
    """Non-existent http_probe path returns empty list."""
    missing = tmp_path / "nonexistent_http_probe.csv"
    assert not missing.exists()
    entries = build_tech_profile_json(missing)
    assert entries == []
