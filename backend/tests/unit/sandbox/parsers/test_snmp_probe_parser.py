"""Unit tests for :mod:`src.sandbox.parsers.snmp_probe_parser` (§4.12 / §4.17).

Pinned contracts:

* ``onesixtyone`` — one finding per ``<ip> [<community>] <descr>`` hit;
  default community (public/private/...) → MISCONFIG (CWE-521),
  otherwise INFO (CWE-200).
* ``snmp_check`` — a readable enumeration report → one finding; default
  community → MISCONFIG, otherwise INFO.  Unstructured text → ``[]``.
* Empty / garbage input returns ``[]``.
* Sidecar JSONL stamped with ``tool_id``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
)
from src.sandbox.parsers.snmp_probe_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_onesixtyone,
    parse_snmp_check,
)

_ONESIXTYONE_OUTPUT = (
    "192.0.2.10 [public] Linux router 5.10.0 x86_64\n"
    "192.0.2.11 [s3cr3t-ro] Cisco IOS Software, Version 15.2\n"
)

_SNMP_CHECK_OUTPUT = (
    "snmp-check v1.9 - SNMP enumerator\n"
    "\n"
    "[+] Try to connect to 192.0.2.10:161 using SNMPv1 and community 'public'\n"
    "\n"
    "[*] System information:\n"
    "\n"
    "  Hostname                      : edge-router-01\n"
    "  Description                   : Linux edge-router-01 5.10.0\n"
    "  Contact                       : ops@contoso.local\n"
    "  Location                      : Rack 14\n"
    "  Uptime system                 : 10 days, 04:11:22\n"
)


# ---------------------------------------------------------------------------
# onesixtyone
# ---------------------------------------------------------------------------


def test_onesixtyone_empty_returns_no_findings(tmp_path: Path) -> None:
    assert parse_onesixtyone(b"", b"", tmp_path, "onesixtyone") == []


def test_onesixtyone_happy_path_two_findings(tmp_path: Path) -> None:
    findings = parse_onesixtyone(_ONESIXTYONE_OUTPUT.encode("utf-8"), b"", tmp_path, "onesixtyone")
    assert len(findings) == 2
    categories = {f.category for f in findings}
    assert FindingCategory.MISCONFIG in categories
    assert FindingCategory.INFO in categories


def test_onesixtyone_default_community_is_misconfig(tmp_path: Path) -> None:
    findings = parse_onesixtyone(
        b"192.0.2.10 [public] Linux router\n", b"", tmp_path, "onesixtyone"
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.MISCONFIG
    assert 521 in findings[0].cwe
    assert findings[0].confidence is ConfidenceLevel.LIKELY


def test_onesixtyone_custom_community_is_info(tmp_path: Path) -> None:
    findings = parse_onesixtyone(
        b"192.0.2.11 [s3cr3t-ro] Cisco IOS\n", b"", tmp_path, "onesixtyone"
    )
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert 200 in findings[0].cwe


def test_onesixtyone_dedup(tmp_path: Path) -> None:
    payload = b"192.0.2.10 [public] a\n192.0.2.10 [public] a\n"
    findings = parse_onesixtyone(payload, b"", tmp_path, "onesixtyone")
    assert len(findings) == 1


def test_onesixtyone_garbage_returns_no_findings(tmp_path: Path) -> None:
    assert parse_onesixtyone(b"no brackets here\n", b"", tmp_path, "onesixtyone") == []


def test_onesixtyone_sidecar_tool_id(tmp_path: Path) -> None:
    parse_onesixtyone(_ONESIXTYONE_OUTPUT.encode("utf-8"), b"", tmp_path, "onesixtyone")
    lines = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()
    records = [json.loads(line) for line in lines if line.strip()]
    assert all(rec["tool_id"] == "onesixtyone" for rec in records)


# ---------------------------------------------------------------------------
# snmp_check
# ---------------------------------------------------------------------------


def test_snmp_check_empty_returns_no_findings(tmp_path: Path) -> None:
    assert parse_snmp_check(b"", b"", tmp_path, "snmp_check") == []


def test_snmp_check_default_community_misconfig(tmp_path: Path) -> None:
    findings = parse_snmp_check(_SNMP_CHECK_OUTPUT.encode("utf-8"), b"", tmp_path, "snmp_check")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.MISCONFIG
    assert 521 in findings[0].cwe


def test_snmp_check_custom_community_info(tmp_path: Path) -> None:
    text = _SNMP_CHECK_OUTPUT.replace("community 'public'", "community 'monitorRO'")
    findings = parse_snmp_check(text.encode("utf-8"), b"", tmp_path, "snmp_check")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO
    assert findings[0].confidence is ConfidenceLevel.CONFIRMED


def test_snmp_check_sidecar_captures_fields(tmp_path: Path) -> None:
    parse_snmp_check(_SNMP_CHECK_OUTPUT.encode("utf-8"), b"", tmp_path, "snmp_check")
    record = json.loads((tmp_path / EVIDENCE_SIDECAR_NAME).read_text("utf-8").splitlines()[0])
    assert record["tool_id"] == "snmp_check"
    assert record["hostname"] == "edge-router-01"
    assert record["contact"] == "ops@contoso.local"


def test_snmp_check_unstructured_text_returns_no_findings(tmp_path: Path) -> None:
    payload = b"some random log line\nanother line\n"
    assert parse_snmp_check(payload, b"", tmp_path, "snmp_check") == []
