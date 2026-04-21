"""Unit tests for :mod:`src.sandbox.parsers.smbmap_parser`.

Pinned contracts (Backlog/dev1_md §4.2 — ARG-022):

* Per-host header ``[+] IP: a.b.c.d:445  Name: …  Status: …`` opens
  a new share-table context.
* Share-row permissions ladder:
  - ``READ, WRITE`` → MISCONFIG HIGH (CVSS 8.5, CWE-732 + CWE-200).
  - ``READ ONLY`` non-baseline share → INFO MEDIUM (CVSS 5.3).
  - ``READ ONLY`` baseline (``IPC$`` / ``ADMIN$`` / ``NETLOGON`` /
    ``SYSVOL``) → INFO LOW (CVSS 3.7).
  - ``NO ACCESS`` → no finding emitted.
* Empty / no-table input → ``[]``.
* Sidecar JSONL stamped with ``tool_id``.
* Dedup on ``(ip, share.lower(), permission)``.
* Sorting prioritises writable shares first, then sensitive readable.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    SSVCDecision,
)
from src.sandbox.parsers.smbmap_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_smbmap,
)


def _smbmap_report() -> bytes:
    return (
        b"[+] IP: 10.0.0.42:445\tName: dc01.contoso.local\tStatus: Authenticated\n"
        b"\tDisk                                              \tPermissions\tComment\n"
        b"\t----                                              \t-----------\t-------\n"
        b"\tADMIN$                                            \tNO ACCESS\tRemote Admin\n"
        b"\tIPC$                                              \tREAD ONLY\tRemote IPC\n"
        b"\tPublic                                            \tREAD, WRITE\tPublic share\n"
        b"\tBackups                                           \tREAD ONLY\tDaily backups\n"
        b"\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_smbmap(b"", b"", tmp_path, "smbmap") == []


def test_no_table_yields_no_findings(tmp_path: Path) -> None:
    payload = b"random text\nno header\n"
    assert parse_smbmap(payload, b"", tmp_path, "smbmap") == []


def test_happy_path_skips_no_access_emits_others(tmp_path: Path) -> None:
    findings = parse_smbmap(_smbmap_report(), b"", tmp_path, "smbmap")
    assert len(findings) == 3


def test_writable_share_emits_misconfig_high(tmp_path: Path) -> None:
    payload = (
        b"[+] IP: 10.0.0.42:445\tName: dc01\n"
        b"\tDisk\tPermissions\tComment\n"
        b"\t----\t-----------\t-------\n"
        b"\tPublic                                            \tREAD, WRITE\tShare\n"
    )
    findings = parse_smbmap(payload, b"", tmp_path, "smbmap")
    finding = findings[0]
    assert finding.category is FindingCategory.MISCONFIG
    assert finding.cvss_v3_score == 8.5
    assert finding.ssvc_decision is SSVCDecision.ACT
    assert 732 in finding.cwe


def test_baseline_share_read_only_is_info_low(tmp_path: Path) -> None:
    payload = (
        b"[+] IP: 10.0.0.42:445\tName: dc01\n"
        b"\tDisk\tPermissions\tComment\n"
        b"\t----\t-----------\t-------\n"
        b"\tIPC$                                              \tREAD ONLY\tRemote IPC\n"
    )
    findings = parse_smbmap(payload, b"", tmp_path, "smbmap")
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert finding.cvss_v3_score == 3.7


def test_non_baseline_read_only_is_info_medium(tmp_path: Path) -> None:
    payload = (
        b"[+] IP: 10.0.0.42:445\tName: dc01\n"
        b"\tDisk\tPermissions\tComment\n"
        b"\t----\t-----------\t-------\n"
        b"\tBackups                                           \tREAD ONLY\tBackups\n"
    )
    findings = parse_smbmap(payload, b"", tmp_path, "smbmap")
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert finding.cvss_v3_score == 5.3


def test_dedup_same_ip_share_permission_collapses(tmp_path: Path) -> None:
    payload = (
        b"[+] IP: 10.0.0.42:445\tName: dc01\n"
        b"\tDisk\tPermissions\tComment\n"
        b"\t----\t-----------\t-------\n"
        b"\tPublic                                            \tREAD, WRITE\tx\n"
        b"\tPublic                                            \tREAD, WRITE\ty\n"
    )
    assert len(parse_smbmap(payload, b"", tmp_path, "smbmap")) == 1


def test_writable_shares_sort_before_others(tmp_path: Path) -> None:
    parse_smbmap(_smbmap_report(), b"", tmp_path, "smbmap")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    first = json.loads(sidecar.splitlines()[0])
    assert first["writable"] is True


def test_sidecar_captures_host_and_tool_id(tmp_path: Path) -> None:
    parse_smbmap(_smbmap_report(), b"", tmp_path, "smbmap")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "smbmap"
    assert record["ip"] == "10.0.0.42:445"
    assert record["host"] == "dc01.contoso.local"


def test_multiple_hosts_each_yield_findings(tmp_path: Path) -> None:
    payload = (
        b"[+] IP: 10.0.0.42:445\tName: dc01\n"
        b"\tDisk\tPermissions\tComment\n"
        b"\t----\t-----------\t-------\n"
        b"\tPublic                                            \tREAD, WRITE\tx\n"
        b"\n"
        b"[+] IP: 10.0.0.43:445\tName: ws01\n"
        b"\tDisk\tPermissions\tComment\n"
        b"\t----\t-----------\t-------\n"
        b"\tShared                                            \tREAD ONLY\ty\n"
    )
    findings = parse_smbmap(payload, b"", tmp_path, "smbmap")
    assert len(findings) == 2


def test_findings_confirmed(tmp_path: Path) -> None:
    findings = parse_smbmap(_smbmap_report(), b"", tmp_path, "smbmap")
    for finding in findings:
        assert finding.confidence is ConfidenceLevel.CONFIRMED
