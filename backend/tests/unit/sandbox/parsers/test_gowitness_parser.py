"""Unit tests for :mod:`src.sandbox.parsers.gowitness_parser` (ARG-032).

Pinned contracts:

* Empty / missing manifest ⇒ ``[]``.
* One INFO finding per ``(host, status_class, title_hash)``.
* URL credentials redacted before sidecar.
* Raster bytes never appear in evidence — only the screenshot file
  basename.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.gowitness_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_gowitness,
)


def _write_manifest(artifact_dir: Path, items: list[dict]) -> None:
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "screenshots.json").write_text(json.dumps(items), encoding="utf-8")


def test_empty_artifacts_returns_no_findings(tmp_path: Path) -> None:
    assert parse_gowitness(b"", b"", tmp_path, "gowitness") == []


def test_manifest_emits_findings(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path / "screens",
        [
            {
                "url": "https://example.com",
                "title": "Home",
                "status": 200,
                "filename": "a.png",
            },
            {
                "url": "https://other.com",
                "title": "Other",
                "status": 200,
                "filename": "b.png",
            },
        ],
    )
    findings = parse_gowitness(b"", b"", tmp_path, "gowitness")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.INFO for f in findings)


def test_url_credentials_redacted(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path / "screens",
        [{"url": "https://user:hunter2@example.com/", "filename": "x.png"}],
    )
    parse_gowitness(b"", b"", tmp_path, "gowitness")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "hunter2" not in sidecar


def test_dedup_on_host_status_title(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path / "screens",
        [
            {
                "url": "https://example.com/a",
                "title": "T",
                "status": 200,
                "filename": "a.png",
            },
            {
                "url": "https://example.com/b",
                "title": "T",
                "status": 200,
                "filename": "b.png",
            },
        ],
    )
    findings = parse_gowitness(b"", b"", tmp_path, "gowitness")
    assert len(findings) == 1


def test_path_traversal_filename_normalised(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path / "screens",
        [{"url": "https://x.example/", "filename": "../../etc/passwd.png"}],
    )
    parse_gowitness(b"", b"", tmp_path, "gowitness")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["screenshot_file"] == "passwd.png"


def test_screenshots_envelope_supported(tmp_path: Path) -> None:
    artifact_dir = tmp_path / "screens"
    artifact_dir.mkdir()
    payload = {"screenshots": [{"url": "https://x.example/", "filename": "x.png"}]}
    (artifact_dir / "screenshots.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    findings = parse_gowitness(b"", b"", tmp_path, "gowitness")
    assert len(findings) == 1


def test_status_class_used_for_dedup(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path / "screens",
        [
            {
                "url": "https://x.example/",
                "title": "T",
                "status": 200,
                "filename": "a.png",
            },
            {
                "url": "https://x.example/",
                "title": "T",
                "status": 201,
                "filename": "b.png",
            },
        ],
    )
    # Both 200 and 201 fall in the 2xx class with same title -> dedup to 1.
    findings = parse_gowitness(b"", b"", tmp_path, "gowitness")
    assert len(findings) == 1
