"""Unit tests for :mod:`src.sandbox.parsers.redis_cli_probe_parser` (ARG-032).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* ``requirepass:false`` (or unset) emits a HIGH MISCONFIG (CWE-306).
* Truthy ``requirepass:yes`` emits NO password finding.
* Server version yields an INFO fingerprint.
* ``role:`` line yields an INFO record.
* ``maxmemory:0`` yields a MEDIUM MISCONFIG (memory uncapped).
* Canonical artifact ``redis_info.txt`` overrides stdout.
* Sidecar JSONL stamped with ``tool_id`` and 12-char ``fingerprint_hash``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.redis_cli_probe_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_redis_cli_probe,
)


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_redis_cli_probe(b"", b"", tmp_path, "redis_cli_probe") == []


def test_no_password_emits_high_misconfig(tmp_path: Path) -> None:
    stdout = b"requirepass:false\nredis_version:6.2.6\nrole:master\n"
    findings = parse_redis_cli_probe(stdout, b"", tmp_path, "redis_cli_probe")
    misconfigs = [f for f in findings if f.category is FindingCategory.MISCONFIG]
    assert any(f.cvss_v3_score >= 9.0 for f in misconfigs)
    high = [f for f in misconfigs if f.cvss_v3_score >= 9.0][0]
    assert high.confidence is ConfidenceLevel.CONFIRMED
    assert 306 in high.cwe


def test_password_set_yields_no_password_finding(tmp_path: Path) -> None:
    stdout = b"requirepass:yes\nredis_version:6.2.6\n"
    findings = parse_redis_cli_probe(stdout, b"", tmp_path, "redis_cli_probe")
    misconfigs = [f for f in findings if f.category is FindingCategory.MISCONFIG]
    # No high MISCONFIG present (only INFO version)
    assert len([f for f in misconfigs if f.cvss_v3_score >= 9.0]) == 0


def test_version_emits_info_finding(tmp_path: Path) -> None:
    stdout = b"requirepass:yes\nredis_version:6.2.6\n"
    findings = parse_redis_cli_probe(stdout, b"", tmp_path, "redis_cli_probe")
    info = [f for f in findings if f.category is FindingCategory.INFO]
    assert any(200 in f.cwe for f in info)


def test_maxmemory_zero_emits_medium_misconfig(tmp_path: Path) -> None:
    stdout = b"requirepass:yes\nredis_version:6.2.6\nmaxmemory:0\n"
    findings = parse_redis_cli_probe(stdout, b"", tmp_path, "redis_cli_probe")
    misconfigs = [f for f in findings if f.category is FindingCategory.MISCONFIG]
    medium = [f for f in misconfigs if 4.0 <= f.cvss_v3_score < 7.0]
    assert len(medium) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "redis_info.txt").write_bytes(b"requirepass:yes\nredis_version:7.0.0\n")
    decoy = b"requirepass:false\nredis_version:6.0.0\n"
    findings = parse_redis_cli_probe(decoy, b"", tmp_path, "redis_cli_probe")
    misconfigs = [f for f in findings if f.category is FindingCategory.MISCONFIG]
    assert len([f for f in misconfigs if f.cvss_v3_score >= 9.0]) == 0
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "7.0.0" in sidecar


def test_sidecar_records_tool_id_and_fingerprint(tmp_path: Path) -> None:
    parse_redis_cli_probe(
        b"requirepass:yes\nredis_version:6.2.6\n",
        b"",
        tmp_path,
        "redis_cli_probe",
    )
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines()]
    assert all(r["tool_id"] == "redis_cli_probe" for r in records)
    assert all(isinstance(r["fingerprint_hash"], str) for r in records)
    assert all(len(r["fingerprint_hash"]) == 12 for r in records)


def test_role_line_emits_info(tmp_path: Path) -> None:
    stdout = b"requirepass:yes\nredis_version:6.2.6\nrole:master\n"
    findings = parse_redis_cli_probe(stdout, b"", tmp_path, "redis_cli_probe")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "role_observed" in sidecar
    assert any(f.category is FindingCategory.INFO for f in findings)


def test_dedup_on_repeated_kinds(tmp_path: Path) -> None:
    stdout = b"requirepass:yes\nredis_version:6.2.6\nredis_version:6.2.6\nrole:master\n"
    findings = parse_redis_cli_probe(stdout, b"", tmp_path, "redis_cli_probe")
    # Should be 2 INFO findings: version + role (no dup version)
    assert len(findings) == 2
