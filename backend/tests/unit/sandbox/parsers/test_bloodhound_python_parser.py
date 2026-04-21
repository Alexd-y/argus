"""Unit tests for :mod:`src.sandbox.parsers.bloodhound_python_parser`.

Pinned contracts (Backlog/dev1_md §4.17 — ARG-022):

* Recognises ZIP creation markers (``Compressing output into …`` /
  ``INFO: Wrote …``) and emits one INFO finding per unique zip path.
* Captures discovered AD domain (``Found AD domain: …``).
* Captures DC LDAP server endpoints and per-object counts
  (users / groups / computers / sessions / trusts).
* Falls back to one ``bloodhound_collection_run`` finding when no
  zip line is present but a domain marker is.
* Empty stdout + stderr → no findings, no sidecar.
* Sidecar JSONL stamped with ``tool_id``.
* Severity ladder: every finding is INFO/SUSPECTED/CVSS 0.0.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    SSVCDecision,
)
from src.sandbox.parsers.bloodhound_python_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_bloodhound_python,
)


def _bloodhound_log() -> bytes:
    return (
        b"INFO: Found AD domain: contoso.local\n"
        b"INFO: Connecting to LDAP server: dc01.contoso.local\n"
        b"INFO: Connecting to GC LDAP server: dc01.contoso.local\n"
        b"INFO: Found 312 users\n"
        b"INFO: Found 84 groups\n"
        b"INFO: Found 8 trusts\n"
        b"INFO: Done in 00M 12S\n"
        b"[+] Compressing output into 20260419_BloodHound.zip\n"
    )


def test_empty_stdout_and_stderr_returns_no_findings(tmp_path: Path) -> None:
    assert parse_bloodhound_python(b"", b"", tmp_path, "bloodhound_python") == []


def test_happy_path_emits_finding_for_zip_marker(tmp_path: Path) -> None:
    findings = parse_bloodhound_python(
        _bloodhound_log(), b"", tmp_path, "bloodhound_python"
    )
    assert len(findings) >= 1
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert finding.confidence is ConfidenceLevel.SUSPECTED
    assert finding.cvss_v3_score == 0.0
    assert finding.ssvc_decision is SSVCDecision.TRACK


def test_sidecar_captures_domain_and_zip_path(tmp_path: Path) -> None:
    parse_bloodhound_python(_bloodhound_log(), b"", tmp_path, "bloodhound_python")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "bloodhound_python"
    assert record["domain"] == "contoso.local"
    assert "20260419_BloodHound.zip" in record["zip_path"]


def test_object_counts_are_captured(tmp_path: Path) -> None:
    parse_bloodhound_python(_bloodhound_log(), b"", tmp_path, "bloodhound_python")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    counts = record.get("object_counts", {})
    assert counts.get("users") == 312
    assert counts.get("groups") == 84
    assert counts.get("trusts") == 8


def test_dedup_zip_marker_appearing_twice(tmp_path: Path) -> None:
    payload = (
        b"INFO: Found AD domain: contoso.local\n"
        b"[+] Compressing output into a.zip\n"
        b"INFO: Wrote a.zip\n"
    )
    findings = parse_bloodhound_python(payload, b"", tmp_path, "bloodhound_python")
    assert len(findings) == 1


def test_multiple_zips_emit_distinct_findings(tmp_path: Path) -> None:
    payload = (
        b"INFO: Found AD domain: contoso.local\n"
        b"[+] Compressing output into a.zip\n"
        b"[+] Compressing output into b.zip\n"
    )
    findings = parse_bloodhound_python(payload, b"", tmp_path, "bloodhound_python")
    assert len(findings) == 2


def test_no_zip_but_domain_emits_collection_run(tmp_path: Path) -> None:
    payload = b"INFO: Found AD domain: contoso.local\n"
    findings = parse_bloodhound_python(payload, b"", tmp_path, "bloodhound_python")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["kind"] == "bloodhound_collection_run"


def test_uses_stderr_when_stdout_empty(tmp_path: Path) -> None:
    findings = parse_bloodhound_python(
        b"", _bloodhound_log(), tmp_path, "bloodhound_python"
    )
    assert len(findings) == 1


def test_garbage_lines_yield_no_findings(tmp_path: Path) -> None:
    findings = parse_bloodhound_python(
        b"random text\nno markers here\n", b"", tmp_path, "bloodhound_python"
    )
    assert findings == []


def test_dcs_recorded_in_sidecar(tmp_path: Path) -> None:
    parse_bloodhound_python(_bloodhound_log(), b"", tmp_path, "bloodhound_python")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert "dc01.contoso.local" in record.get("domain_controllers", [])
