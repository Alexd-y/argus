"""Unit tests for :mod:`src.sandbox.parsers.dnsx_parser` (ARG-032 batch 4c).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* JSONL records expand into one INFO finding per ``(host, record_type)``.
* ``wildcard=true`` escalates SOA / TXT records to MISCONFIG.
* Strict RFC-1035 validation drops malformed hostnames.
* Case-insensitive dedup on host.
* Canonical artifact ``dnsx.json`` overrides stdout.
* Sidecar JSONL stamped with ``tool_id`` and 12-char ``fingerprint_hash``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.dnsx_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_dnsx,
)


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_dnsx(b"", b"", tmp_path, "dnsx") == []


def test_a_record_yields_one_info_finding(tmp_path: Path) -> None:
    stdout = b'{"host":"api.example.com","a":["10.0.0.1"]}\n'
    findings = parse_dnsx(stdout, b"", tmp_path, "dnsx")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert 200 in findings[0].cwe


def test_multiple_record_types_emit_separate_findings(tmp_path: Path) -> None:
    stdout = (
        b'{"host":"api.example.com","a":["10.0.0.1"],"cname":["api-prod.example.com"],'
        b'"mx":["10 mx1.example.com"]}\n'
    )
    findings = parse_dnsx(stdout, b"", tmp_path, "dnsx")
    assert len(findings) == 3


def test_wildcard_soa_escalates_to_misconfig(tmp_path: Path) -> None:
    stdout = (
        b'{"host":"api.example.com","wildcard":true,'
        b'"soa":["ns1.example.com hostmaster.example.com 1 7200 1800 1209600 3600"]}\n'
    )
    findings = parse_dnsx(stdout, b"", tmp_path, "dnsx")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.MISCONFIG


def test_invalid_hostname_dropped(tmp_path: Path) -> None:
    stdout = b'{"host":"not..valid","a":["10.0.0.1"]}\n'
    assert parse_dnsx(stdout, b"", tmp_path, "dnsx") == []


def test_dedup_collapses_duplicate_records(tmp_path: Path) -> None:
    stdout = (
        b'{"host":"api.example.com","a":["10.0.0.1"]}\n'
        b'{"host":"api.example.com","a":["10.0.0.2"]}\n'
    )
    findings = parse_dnsx(stdout, b"", tmp_path, "dnsx")
    assert len(findings) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "dnsx.json").write_bytes(
        b'{"host":"canonical.example.com","a":["10.0.0.1"]}\n'
    )
    findings = parse_dnsx(
        b'{"host":"decoy.example.com","a":["10.0.0.2"]}\n',
        b"",
        tmp_path,
        "dnsx",
    )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["host"] == "canonical.example.com"


def test_sidecar_records_tool_id_and_fingerprint(tmp_path: Path) -> None:
    parse_dnsx(
        b'{"host":"api.example.com","a":["10.0.0.1"]}\n',
        b"",
        tmp_path,
        "dnsx",
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "dnsx"
    assert record["host"] == "api.example.com"
    assert record["record_type"] == "a"
    assert isinstance(record["fingerprint_hash"], str)
    assert len(record["fingerprint_hash"]) == 12


def test_invalid_record_type_skipped(tmp_path: Path) -> None:
    stdout = b'{"host":"api.example.com","unknown":["xyz"]}\n'
    assert parse_dnsx(stdout, b"", tmp_path, "dnsx") == []
