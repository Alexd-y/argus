"""Unit tests for :mod:`src.sandbox.parsers.snmpwalk_parser`.

Pinned contracts (Backlog/dev1_md §4.17 — ARG-022):

* Recognises the ``OID = TYPE: VALUE`` line shape and aggregates
  ``sysDescr`` / ``sysName`` / ``sysContact`` / ``sysLocation`` /
  ``sysObjectID`` / ``sysUptime`` / ``sysServices`` per host.
* Default community (``public`` / ``private`` / ``manager``) bumps
  severity to MISCONFIG HIGH (CVSS 7.5, CWE-521 + CWE-200).
* Non-default community walks → INFO LOW (CVSS 3.7, CWE-200).
* Empty / unparseable input returns ``[]``.
* Sidecar JSONL stamped with ``tool_id``.
* Truncates extremely long string values defensively.
* Counts interfaces from ``IF-MIB::ifNumber.0`` line.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    SSVCDecision,
)
from src.sandbox.parsers.snmpwalk_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_snmpwalk,
)


def _snmpwalk_output(community: str = "secret") -> bytes:
    return (
        f"# community: {community}\n"
        "SNMPv2-MIB::sysDescr.0 = STRING: Linux router 5.10.0\n"
        "SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.8072\n"
        "SNMPv2-MIB::sysContact.0 = STRING: admin@contoso.local\n"
        "SNMPv2-MIB::sysName.0 = STRING: edge-router-01\n"
        "SNMPv2-MIB::sysLocation.0 = STRING: rack 14\n"
        "IF-MIB::ifNumber.0 = INTEGER: 12\n"
    ).encode("utf-8")


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_snmpwalk(b"", b"", tmp_path, "snmpwalk") == []


def test_happy_path_emits_info_finding_for_walk(tmp_path: Path) -> None:
    findings = parse_snmpwalk(_snmpwalk_output(), b"", tmp_path, "snmpwalk")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert finding.cvss_v3_score == 3.7
    assert 200 in finding.cwe


def test_default_community_escalates_to_misconfig(tmp_path: Path) -> None:
    findings = parse_snmpwalk(
        _snmpwalk_output(community="public"), b"", tmp_path, "snmpwalk"
    )
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.MISCONFIG
    assert finding.cvss_v3_score == 7.5
    assert 521 in finding.cwe
    assert finding.ssvc_decision is SSVCDecision.ATTEND


def test_private_community_also_default(tmp_path: Path) -> None:
    findings = parse_snmpwalk(
        _snmpwalk_output(community="private"), b"", tmp_path, "snmpwalk"
    )
    assert findings[0].category is FindingCategory.MISCONFIG


def test_sidecar_captures_sys_fields(tmp_path: Path) -> None:
    parse_snmpwalk(_snmpwalk_output(), b"", tmp_path, "snmpwalk")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "snmpwalk"
    assert record.get("sys_name") == "edge-router-01"
    assert record.get("sys_contact") == "admin@contoso.local"
    assert record.get("interface_count") == 12


def test_unrecognised_lines_skipped(tmp_path: Path) -> None:
    payload = b"random text\nblah blah\n"
    assert parse_snmpwalk(payload, b"", tmp_path, "snmpwalk") == []


def test_long_string_value_is_truncated(tmp_path: Path) -> None:
    long_str = "X" * 700
    payload = (f"SNMPv2-MIB::sysDescr.0 = STRING: {long_str}\n").encode("utf-8")
    parse_snmpwalk(payload, b"", tmp_path, "snmpwalk")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert "[truncated]" in record["sys_descr"]


def test_uses_stderr_when_stdout_empty(tmp_path: Path) -> None:
    findings = parse_snmpwalk(b"", _snmpwalk_output(), tmp_path, "snmpwalk")
    assert len(findings) == 1


def test_dedup_runs_against_same_host(tmp_path: Path) -> None:
    findings_a = parse_snmpwalk(_snmpwalk_output(), b"", tmp_path, "snmpwalk")
    findings_b = parse_snmpwalk(_snmpwalk_output(), b"", tmp_path, "snmpwalk")
    assert len(findings_a) == len(findings_b) == 1


def test_finding_confidence_for_default_is_confirmed(tmp_path: Path) -> None:
    findings = parse_snmpwalk(
        _snmpwalk_output(community="public"), b"", tmp_path, "snmpwalk"
    )
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED
