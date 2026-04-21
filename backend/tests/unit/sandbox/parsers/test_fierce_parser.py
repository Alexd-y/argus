"""Unit tests for :mod:`src.sandbox.parsers.fierce_parser` (ARG-032).

Pinned contracts:

* Empty stdout ⇒ ``[]``.
* ``found_dns`` records yield INFO findings.
* ``zone_transfer.successful=true`` adds a MISCONFIG finding (CVSS 5.3).
* Hosts are validated against RFC-1035.
* Canonical artifact ``fierce.json`` overrides stdout.
* Sidecar JSONL stamped with ``tool_id``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.fierce_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_fierce,
)


def _payload(
    found: list[dict[str, str]] | None = None, zone: dict | None = None
) -> bytes:
    body: dict[str, object] = {"domain": "example.com"}
    if found is not None:
        body["found_dns"] = found
    if zone is not None:
        body["zone_transfer"] = zone
    return json.dumps(body).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_fierce(b"", b"", tmp_path, "fierce") == []


def test_found_dns_emits_info_findings(tmp_path: Path) -> None:
    stdout = _payload(
        found=[
            {"name": "ns1.example.com", "ip": "1.2.3.4"},
            {"name": "mail.example.com", "ip": "5.6.7.8"},
        ]
    )
    findings = parse_fierce(stdout, b"", tmp_path, "fierce")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.INFO for f in findings)


def test_successful_zone_transfer_emits_misconfig(tmp_path: Path) -> None:
    stdout = _payload(zone={"successful": True})
    findings = parse_fierce(stdout, b"", tmp_path, "fierce")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.MISCONFIG
    assert findings[0].cvss_v3_score == 5.3


def test_invalid_hostnames_skipped(tmp_path: Path) -> None:
    stdout = _payload(found=[{"name": "not_a_host"}, {"name": "valid.example.com"}])
    findings = parse_fierce(stdout, b"", tmp_path, "fierce")
    assert len(findings) == 1


def test_zone_records_count_as_successful(tmp_path: Path) -> None:
    stdout = _payload(zone={"records": [{"name": "internal.example.com"}]})
    findings = parse_fierce(stdout, b"", tmp_path, "fierce")
    assert len(findings) == 2  # zone host + axfr finding


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    canonical = _payload(found=[{"name": "canonical.example.com"}])
    (tmp_path / "fierce.json").write_bytes(canonical)
    decoy = _payload(found=[{"name": "decoy.example.com"}])
    findings = parse_fierce(decoy, b"", tmp_path, "fierce")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example.com" in sidecar


def test_sidecar_marks_kind(tmp_path: Path) -> None:
    parse_fierce(_payload(found=[{"name": "a.example.com"}]), b"", tmp_path, "fierce")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["kind"] == "subdomain"
    assert record["tool_id"] == "fierce"
