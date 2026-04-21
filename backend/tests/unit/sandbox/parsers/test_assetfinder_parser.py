"""Unit tests for :mod:`src.sandbox.parsers.assetfinder_parser` (ARG-032).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* One INFO finding per unique hostname (CWE-200 / CWE-668).
* Strict RFC-1035 validation drops noise / partial / malformed lines.
* Canonical artifact ``assetfinder.txt`` overrides stdout when present.
* Dedup is case-insensitive.
* Sidecar JSONL stamped with ``tool_id``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.assetfinder_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_assetfinder,
)


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_assetfinder(b"", b"", tmp_path, "assetfinder") == []


def test_happy_path_one_finding_per_hostname(tmp_path: Path) -> None:
    stdout = b"api.example.com\ncdn.example.com\nwww.example.com\n"
    findings = parse_assetfinder(stdout, b"", tmp_path, "assetfinder")
    assert len(findings) == 3
    for finding in findings:
        assert finding.category is FindingCategory.INFO
        assert finding.confidence is ConfidenceLevel.CONFIRMED


def test_dedup_case_insensitive(tmp_path: Path) -> None:
    stdout = b"API.example.com\napi.example.com\n"
    assert len(parse_assetfinder(stdout, b"", tmp_path, "assetfinder")) == 1


def test_invalid_lines_skipped(tmp_path: Path) -> None:
    stdout = b"not_a_host\n[+] log line\nfoo bar baz\nvalid.example.com\n"
    findings = parse_assetfinder(stdout, b"", tmp_path, "assetfinder")
    assert len(findings) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "assetfinder.txt").write_bytes(b"canonical.example.com\n")
    decoy = b"decoy.example.com\n"
    findings = parse_assetfinder(decoy, b"", tmp_path, "assetfinder")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example.com" in sidecar
    assert "decoy.example.com" not in sidecar


def test_sidecar_records_tool_id_and_fingerprint(tmp_path: Path) -> None:
    parse_assetfinder(b"api.example.com\n", b"", tmp_path, "assetfinder")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record == {
        "fingerprint_hash": record["fingerprint_hash"],
        "host": "api.example.com",
        "tool_id": "assetfinder",
    }
    assert len(record["fingerprint_hash"]) == 12


def test_blank_lines_ignored(tmp_path: Path) -> None:
    stdout = b"\n\napi.example.com\n\n\n"
    assert len(parse_assetfinder(stdout, b"", tmp_path, "assetfinder")) == 1
