"""Unit tests for :mod:`src.sandbox.parsers.puppeteer_screens_parser` (ARG-032).

CRITICAL security gates (C12 contract):
    * HAR cookies / authorization headers are masked at load time.
    * Manifest URLs route through :func:`redact_password_in_text` before
      sidecar persistence.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.puppeteer_screens_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_puppeteer_screens,
)


def _write_manifest(artifact_dir: Path, items: list[dict]) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "index.json").write_text(json.dumps(items), encoding="utf-8")


def _write_har(artifact_dir: Path, entries: list[dict]) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    har = {"log": {"version": "1.2", "entries": entries}}
    (artifact_dir / "index.har").write_text(json.dumps(har), encoding="utf-8")


def test_empty_artifacts_returns_no_findings(tmp_path: Path) -> None:
    assert parse_puppeteer_screens(b"", b"", tmp_path, "puppeteer_screens") == []


def test_manifest_emits_screenshot_findings(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path / "puppeteer",
        [
            {"url": "https://example.com/", "screenshot": "home.png"},
            {"url": "https://example.com/about", "screenshot": "about.png"},
        ],
    )
    findings = parse_puppeteer_screens(b"", b"", tmp_path, "puppeteer_screens")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.INFO for f in findings)


def test_dedup_collapses_same_path_prefix(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path / "puppeteer",
        [
            {"url": "https://example.com/api/v1/x", "screenshot": "a.png"},
            {"url": "https://example.com/api/v1/x", "screenshot": "a.png"},
        ],
    )
    findings = parse_puppeteer_screens(b"", b"", tmp_path, "puppeteer_screens")
    assert len(findings) == 1


def test_url_credentials_redacted(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path / "puppeteer",
        [{"url": "https://user:hunter2@example.com/", "screenshot": "a.png"}],
    )
    parse_puppeteer_screens(b"", b"", tmp_path, "puppeteer_screens")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "hunter2" not in sidecar


def test_har_entries_emit_findings(tmp_path: Path) -> None:
    _write_har(
        tmp_path / "puppeteer",
        [
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/users",
                    "headers": [],
                },
                "response": {"status": 200, "headers": []},
            }
        ],
    )
    findings = parse_puppeteer_screens(b"", b"", tmp_path, "puppeteer_screens")
    assert len(findings) == 1


def test_har_cookies_redacted(tmp_path: Path) -> None:
    _write_har(
        tmp_path / "puppeteer",
        [
            {
                "request": {
                    "method": "GET",
                    "url": "https://api.example.com/",
                    "headers": [{"name": "Cookie", "value": "session=ABC"}],
                },
                "response": {"status": 200, "headers": []},
            }
        ],
    )
    parse_puppeteer_screens(b"", b"", tmp_path, "puppeteer_screens")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "session=ABC" not in sidecar


def test_screenshots_envelope_supported(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "puppeteer"
    artifact_dir.mkdir()
    payload = {"screenshots": [{"url": "https://x.example/", "screenshot": "x.png"}]}
    (artifact_dir / "index.json").write_text(json.dumps(payload), encoding="utf-8")
    findings = parse_puppeteer_screens(b"", b"", tmp_path, "puppeteer_screens")
    assert len(findings) == 1
