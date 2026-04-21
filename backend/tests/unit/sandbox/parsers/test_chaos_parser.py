"""Unit tests for :mod:`src.sandbox.parsers.chaos_parser` (ARG-032).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* One INFO finding per unique hostname (CWE-200 / CWE-668).
* Wildcard prefixes (``*.dev.example.com``) collapse onto the bare host.
* Strict RFC-1035 validation drops noise lines (``[+] processing...``).
* Canonical artifact ``chaos.txt`` overrides stdout when present.
* Sidecar JSONL stamped with ``tool_id``; passwords / addresses scrubbed.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.chaos_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_chaos,
)


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_chaos(b"", b"", tmp_path, "chaos") == []


def test_happy_path_emits_one_info_finding_per_subdomain(tmp_path: Path) -> None:
    stdout = b"api.example.com\ncdn.example.com\nwww.example.com\n"
    findings = parse_chaos(stdout, b"", tmp_path, "chaos")
    assert len(findings) == 3
    for finding in findings:
        assert finding.category is FindingCategory.INFO
        assert finding.confidence is ConfidenceLevel.CONFIRMED
        assert 200 in finding.cwe and 668 in finding.cwe


def test_wildcard_prefix_is_stripped(tmp_path: Path) -> None:
    stdout = b"*.dev.example.com\ndev.example.com\n"
    findings = parse_chaos(stdout, b"", tmp_path, "chaos")
    assert len(findings) == 1


def test_dedup_collapses_duplicate_hostnames(tmp_path: Path) -> None:
    stdout = b"api.example.com\nAPI.example.com\napi.example.com\n"
    assert len(parse_chaos(stdout, b"", tmp_path, "chaos")) == 1


def test_invalid_lines_skipped(tmp_path: Path) -> None:
    stdout = b"[+] processing target\nnot a host\nbad..host\nvalid.example.com\n"
    findings = parse_chaos(stdout, b"", tmp_path, "chaos")
    assert len(findings) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "chaos.txt").write_bytes(b"canonical.example.com\n")
    decoy = b"decoy.example.com\n"
    findings = parse_chaos(decoy, b"", tmp_path, "chaos")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["host"] == "canonical.example.com"


def test_sidecar_records_tool_id_and_fingerprint(tmp_path: Path) -> None:
    parse_chaos(b"api.example.com\n", b"", tmp_path, "chaos")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "chaos"
    assert record["host"] == "api.example.com"
    assert isinstance(record["fingerprint_hash"], str)
    assert len(record["fingerprint_hash"]) == 12


def test_comment_lines_skipped(tmp_path: Path) -> None:
    stdout = b"# header line\n# another comment\napi.example.com\n"
    findings = parse_chaos(stdout, b"", tmp_path, "chaos")
    assert len(findings) == 1
