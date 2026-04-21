"""Unit tests for :mod:`src.sandbox.parsers.mongodb_probe_parser` (ARG-032).

Pinned contracts:

* Empty stdout / missing host ⇒ ``[]``.
* ``auth_required=false`` emits a HIGH MISCONFIG (CWE-306).
* Per-database INFO findings appear when auth is missing and the
  database list is non-empty.
* Server version string yields an INFO fingerprint regardless of
  auth state.
* Authenticated targets emit ONLY the version INFO finding.
* Canonical artifact ``mongo_info.json`` overrides stdout.
* Sidecar JSONL stamped with ``tool_id`` and 12-char ``fingerprint_hash``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.mongodb_probe_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_mongodb_probe,
)


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_mongodb_probe(b"", b"", tmp_path, "mongodb_probe") == []


def test_missing_host_returns_no_findings(tmp_path: Path) -> None:
    payload = json.dumps({"auth_required": False, "version": "4.4.6"}).encode("utf-8")
    assert parse_mongodb_probe(payload, b"", tmp_path, "mongodb_probe") == []


def test_unauthenticated_emits_high_misconfig(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "host": "10.0.0.10:27017",
            "version": "4.4.6",
            "auth_required": False,
            "databases": [{"name": "admin"}, {"name": "users"}],
        }
    ).encode("utf-8")
    findings = parse_mongodb_probe(payload, b"", tmp_path, "mongodb_probe")
    misconfigs = [f for f in findings if f.category is FindingCategory.MISCONFIG]
    assert len(misconfigs) == 1
    assert misconfigs[0].cvss_v3_score >= 9.0
    assert misconfigs[0].confidence is ConfidenceLevel.CONFIRMED
    assert 306 in misconfigs[0].cwe


def test_authenticated_only_yields_version_info(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "host": "10.0.0.10:27017",
            "version": "4.4.6",
            "auth_required": True,
            "databases": [{"name": "admin"}],
        }
    ).encode("utf-8")
    findings = parse_mongodb_probe(payload, b"", tmp_path, "mongodb_probe")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO


def test_unauth_emits_per_database_info(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "host": "10.0.0.10:27017",
            "version": "4.4.6",
            "auth_required": False,
            "databases": [{"name": "admin"}, {"name": "users"}, "config"],
        }
    ).encode("utf-8")
    findings = parse_mongodb_probe(payload, b"", tmp_path, "mongodb_probe")
    info_findings = [f for f in findings if f.category is FindingCategory.INFO]
    # 1 version + 3 dbs (admin, users, config)
    assert len(info_findings) == 4


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = json.dumps(
        {"host": "10.0.0.99:27017", "version": "5.0.0", "auth_required": True}
    ).encode("utf-8")
    (tmp_path / "mongo_info.json").write_bytes(canonical)
    decoy = json.dumps(
        {"host": "1.1.1.1:27017", "version": "4.4.6", "auth_required": True}
    ).encode("utf-8")
    findings = parse_mongodb_probe(decoy, b"", tmp_path, "mongodb_probe")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["host"] == "10.0.0.99:27017"
    assert record["subject"] == "5.0.0"


def test_sidecar_records_tool_id_and_fingerprint(tmp_path: Path) -> None:
    payload = json.dumps(
        {"host": "10.0.0.10:27017", "version": "4.4.6", "auth_required": True}
    ).encode("utf-8")
    parse_mongodb_probe(payload, b"", tmp_path, "mongodb_probe")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "mongodb_probe"
    assert record["host"] == "10.0.0.10:27017"
    assert record["kind"] == "version_disclosed"
    assert isinstance(record["fingerprint_hash"], str)
    assert len(record["fingerprint_hash"]) == 12


def test_dedup_on_repeated_database_names(tmp_path: Path) -> None:
    payload = json.dumps(
        {
            "host": "10.0.0.10:27017",
            "version": "4.4.6",
            "auth_required": False,
            "databases": [{"name": "admin"}, {"name": "ADMIN"}, {"name": "admin"}],
        }
    ).encode("utf-8")
    findings = parse_mongodb_probe(payload, b"", tmp_path, "mongodb_probe")
    info = [f for f in findings if f.category is FindingCategory.INFO]
    # 1 version + 1 unique db (admin, ADMIN, admin all collapse)
    assert len(info) == 2
