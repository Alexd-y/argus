"""Unit tests for :mod:`src.sandbox.parsers.apktool_parser` (ARG-032).

Pinned contracts:

* ``android:debuggable="true"`` ⇒ MISCONFIG (CVSS 7.8, CWE-489).
* ``android:allowBackup="true"`` ⇒ MISCONFIG (CWE-200).
* ``cleartextTrafficPermitted=true`` ⇒ CRYPTO (CWE-319).
* ``targetSdkVersion < 24`` ⇒ INFO (deprecated SDK).
* WARN/ERROR log lines emit INFO findings up to a cap.
"""

from __future__ import annotations

from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.apktool_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_apktool,
)


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_apktool(b"", b"", tmp_path, "apktool") == []


def test_debuggable_emits_misconfig(tmp_path: Path) -> None:
    payload = b'I: <application android:debuggable="true">\n'
    findings = parse_apktool(payload, b"", tmp_path, "apktool")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.MISCONFIG
    assert findings[0].cvss_v3_score == 7.8
    assert 489 in findings[0].cwe


def test_allow_backup_emits_misconfig(tmp_path: Path) -> None:
    payload = b'I: <application android:allowBackup="true">\n'
    findings = parse_apktool(payload, b"", tmp_path, "apktool")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.MISCONFIG


def test_cleartext_traffic_emits_crypto(tmp_path: Path) -> None:
    payload = b"I: cleartextTrafficPermitted=true\n"
    findings = parse_apktool(payload, b"", tmp_path, "apktool")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.CRYPTO
    assert 319 in findings[0].cwe


def test_deprecated_sdk_emits_info(tmp_path: Path) -> None:
    payload = b"I: targetSdkVersion=22\n"
    findings = parse_apktool(payload, b"", tmp_path, "apktool")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO


def test_recent_sdk_does_not_trigger(tmp_path: Path) -> None:
    payload = b"I: targetSdkVersion=33\n"
    assert parse_apktool(payload, b"", tmp_path, "apktool") == []


def test_warn_lines_emit_info_findings(tmp_path: Path) -> None:
    payload = b"W: failed to decode resource id 0x7f010001\n"
    findings = parse_apktool(payload, b"", tmp_path, "apktool")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.INFO


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "apktool.log").write_bytes(b'I: android:debuggable="true"\n')
    decoy = b"I: targetSdkVersion=22\n"
    findings = parse_apktool(decoy, b"", tmp_path, "apktool")
    assert len(findings) == 1
    assert findings[0].category is FindingCategory.MISCONFIG


def test_sidecar_records_tool_id(tmp_path: Path) -> None:
    parse_apktool(b'I: android:debuggable="true"\n', b"", tmp_path, "apktool")
    assert (tmp_path / EVIDENCE_SIDECAR_NAME).is_file()
