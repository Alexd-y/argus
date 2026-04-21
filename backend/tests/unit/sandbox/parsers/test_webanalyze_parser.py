"""Unit tests for :mod:`src.sandbox.parsers.webanalyze_parser` (ARG-032).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* One INFO finding per ``(hostname, app_name, major_version)``.
* Confidence ladder: ≥ 75 → CONFIRMED; ≥ 50 → LIKELY; otherwise SUSPECTED.
* Categories normalised + sorted.
* Canonical artifact ``webanalyze.json`` takes precedence.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.webanalyze_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_webanalyze,
)


def _payload(records=None) -> bytes:
    return json.dumps(records or []).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_webanalyze(b"", b"", tmp_path, "webanalyze") == []


def test_one_finding_per_match(tmp_path: Path) -> None:
    payload = _payload(
        [
            {
                "hostname": "example.com",
                "matches": [
                    {"app_name": "Apache", "version": "2.4.41", "confidence": 100},
                    {"app_name": "PHP", "version": "7.4.3", "confidence": 80},
                ],
            }
        ]
    )
    findings = parse_webanalyze(payload, b"", tmp_path, "webanalyze")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.INFO for f in findings)


def test_confidence_ladder(tmp_path: Path) -> None:
    payload = _payload(
        [
            {
                "hostname": "example.com",
                "matches": [
                    {"app_name": "A", "version": "1", "confidence": 100},
                    {"app_name": "B", "version": "1", "confidence": 60},
                    {"app_name": "C", "version": "1", "confidence": 30},
                ],
            }
        ]
    )
    findings = parse_webanalyze(payload, b"", tmp_path, "webanalyze")
    confidences = sorted(f.confidence for f in findings)
    assert ConfidenceLevel.CONFIRMED in confidences
    assert ConfidenceLevel.LIKELY in confidences
    assert ConfidenceLevel.SUSPECTED in confidences


def test_dedup_on_hostname_app_major_version(tmp_path: Path) -> None:
    payload = _payload(
        [
            {
                "hostname": "example.com",
                "matches": [
                    {"app_name": "Apache", "version": "2.4.41"},
                    {"app_name": "Apache", "version": "2.4.42"},
                ],
            }
        ]
    )
    findings = parse_webanalyze(payload, b"", tmp_path, "webanalyze")
    assert len(findings) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = _payload(
        [
            {
                "hostname": "canonical.example",
                "matches": [{"app_name": "X", "version": "1"}],
            }
        ]
    )
    (tmp_path / "webanalyze.json").write_bytes(canonical)
    decoy = _payload(
        [{"hostname": "decoy.example", "matches": [{"app_name": "Y", "version": "1"}]}]
    )
    parse_webanalyze(decoy, b"", tmp_path, "webanalyze")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example" in sidecar
    assert "decoy.example" not in sidecar


def test_categories_sorted_and_unique(tmp_path: Path) -> None:
    payload = _payload(
        [
            {
                "hostname": "example.com",
                "matches": [
                    {
                        "app_name": "Apache",
                        "version": "2.4",
                        "categories": ["B", "A", "B"],
                    }
                ],
            }
        ]
    )
    parse_webanalyze(payload, b"", tmp_path, "webanalyze")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["categories"] == ["A", "B"]


def test_records_envelope_supported(tmp_path: Path) -> None:
    payload = json.dumps(
        {"results": [{"hostname": "x.example", "matches": [{"app_name": "Z"}]}]}
    ).encode()
    assert len(parse_webanalyze(payload, b"", tmp_path, "webanalyze")) == 1
