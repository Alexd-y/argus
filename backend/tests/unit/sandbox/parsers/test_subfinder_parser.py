"""Unit tests for :mod:`src.sandbox.parsers.subfinder_parser` (ARG-032).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* Both JSONL and bare-hostname text shapes accepted.
* One INFO finding per unique hostname (case-insensitive dedup).
* Strict RFC-1035 validation drops noise.
* Canonical artifact ``subfinder.json`` overrides stdout.
* Sidecar JSONL stamped with ``tool_id``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.subfinder_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_subfinder,
)


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_subfinder(b"", b"", tmp_path, "subfinder") == []


def test_jsonl_shape_yields_one_finding_per_host(tmp_path: Path) -> None:
    stdout = (
        b'{"host":"api.example.com","input":"example.com","source":"crtsh"}\n'
        b'{"host":"cdn.example.com","input":"example.com","source":"chaos"}\n'
    )
    findings = parse_subfinder(stdout, b"", tmp_path, "subfinder")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.INFO for f in findings)


def test_plaintext_shape_supported(tmp_path: Path) -> None:
    stdout = b"api.example.com\ncdn.example.com\n"
    findings = parse_subfinder(stdout, b"", tmp_path, "subfinder")
    assert len(findings) == 2


def test_dedup_case_insensitive(tmp_path: Path) -> None:
    stdout = b'{"host":"API.example.com"}\napi.example.com\n'
    assert len(parse_subfinder(stdout, b"", tmp_path, "subfinder")) == 1


def test_invalid_lines_skipped(tmp_path: Path) -> None:
    stdout = b"[+] processing\nnot a host\nvalid.example.com\n"
    findings = parse_subfinder(stdout, b"", tmp_path, "subfinder")
    assert len(findings) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "subfinder.json").write_bytes(b"canonical.example.com\n")
    findings = parse_subfinder(b"decoy.example.com\n", b"", tmp_path, "subfinder")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example.com" in sidecar


def test_sidecar_records_input_and_source(tmp_path: Path) -> None:
    stdout = b'{"host":"api.example.com","input":"example.com","source":"crtsh"}\n'
    parse_subfinder(stdout, b"", tmp_path, "subfinder")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "subfinder"
    assert record["host"] == "api.example.com"
    assert record["source"] == "crtsh"
    assert record["input"] == "example.com"
