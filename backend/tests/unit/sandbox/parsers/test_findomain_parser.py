"""Unit tests for :mod:`src.sandbox.parsers.findomain_parser` (ARG-032).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* One INFO finding per unique hostname.
* Strict RFC-1035 validation drops noise.
* Canonical artifact ``findomain.txt`` overrides stdout.
* Dedup is case-insensitive.
* Sidecar JSONL stamped with ``tool_id``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.findomain_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_findomain,
)


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_findomain(b"", b"", tmp_path, "findomain") == []


def test_one_finding_per_hostname(tmp_path: Path) -> None:
    stdout = b"api.example.com\ncdn.example.com\n"
    findings = parse_findomain(stdout, b"", tmp_path, "findomain")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.INFO for f in findings)


def test_dedup_case_insensitive(tmp_path: Path) -> None:
    stdout = b"API.example.com\napi.EXAMPLE.com\n"
    assert len(parse_findomain(stdout, b"", tmp_path, "findomain")) == 1


def test_invalid_lines_skipped(tmp_path: Path) -> None:
    stdout = b"+----+\n| target |\n+----+\n| api.example.com |\nvalid.example.com\n"
    findings = parse_findomain(stdout, b"", tmp_path, "findomain")
    assert len(findings) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "findomain.txt").write_bytes(b"canonical.example.com\n")
    findings = parse_findomain(b"decoy.example.com\n", b"", tmp_path, "findomain")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example.com" in sidecar


def test_sidecar_emits_tool_id_and_host(tmp_path: Path) -> None:
    parse_findomain(b"api.example.com\n", b"", tmp_path, "findomain")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "findomain"
    assert record["host"] == "api.example.com"


def test_blank_lines_skipped(tmp_path: Path) -> None:
    stdout = b"\n\napi.example.com\n\n"
    assert len(parse_findomain(b"" + stdout, b"", tmp_path, "findomain")) == 1
