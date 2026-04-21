"""Unit tests for :mod:`src.sandbox.parsers.smbclient_check_parser`.

Pinned contracts (Backlog/dev1_md §4.12 — ARG-022):

* ``Sharename / Type / Comment`` table rows are extracted into
  per-share findings.
* Administrative shares (``ADMIN$`` / ``C$`` / ``IPC$`` / ``NETLOGON``
  / ``SYSVOL`` / ``PRINT$`` / ``[A-Z]$``) escalate to MISCONFIG
  MEDIUM (CVSS 6.5, CWE-200 + CWE-285).
* Regular shares → INFO LOW (CVSS 3.7, CWE-200).
* Empty / no-table input → ``[]``.
* Sidecar JSONL stamped with ``tool_id``.
* Dedup on ``(kind, share_name.lower())``.
* Workgroup / Server tables outside the share section are ignored.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    SSVCDecision,
)
from src.sandbox.parsers.smbclient_check_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_smbclient_check,
)


def _smbclient_listing() -> bytes:
    return (
        b"\tSharename       Type      Comment\n"
        b"\t---------       ----      -------\n"
        b"\tADMIN$          Disk      Remote Admin\n"
        b"\tC$              Disk      Default share\n"
        b"\tIPC$            IPC       Remote IPC\n"
        b"\tPublic          Disk      Public share\n"
        b"\tBackups         Disk      Daily backups\n"
        b"\n"
        b"Reconnecting with SMB1 for workgroup listing.\n"
        b"\n"
        b"\tServer               Comment\n"
        b"\t---------            -------\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_smbclient_check(b"", b"", tmp_path, "smbclient") == []


def test_no_table_in_input_yields_no_findings(tmp_path: Path) -> None:
    payload = b"random text\nnone of this is a share table\n"
    assert parse_smbclient_check(payload, b"", tmp_path, "smbclient") == []


def test_happy_path_emits_finding_per_share(tmp_path: Path) -> None:
    findings = parse_smbclient_check(_smbclient_listing(), b"", tmp_path, "smbclient")
    assert len(findings) == 5


def test_admin_shares_emit_misconfig_medium(tmp_path: Path) -> None:
    payload = (
        b"\tSharename       Type      Comment\n"
        b"\t---------       ----      -------\n"
        b"\tADMIN$          Disk      Remote Admin\n"
    )
    findings = parse_smbclient_check(payload, b"", tmp_path, "smbclient")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.MISCONFIG
    assert finding.cvss_v3_score == 6.5
    assert finding.ssvc_decision is SSVCDecision.ATTEND


def test_regular_share_emits_info_low(tmp_path: Path) -> None:
    payload = (
        b"\tSharename       Type      Comment\n"
        b"\t---------       ----      -------\n"
        b"\tPublic          Disk      Public share\n"
    )
    findings = parse_smbclient_check(payload, b"", tmp_path, "smbclient")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert finding.cvss_v3_score == 3.7


def test_dedup_collapses_duplicate_share_lines(tmp_path: Path) -> None:
    payload = (
        b"\tSharename       Type      Comment\n"
        b"\t---------       ----      -------\n"
        b"\tPublic          Disk      x\n"
        b"\tPublic          Disk      duplicate\n"
    )
    assert len(parse_smbclient_check(payload, b"", tmp_path, "smbclient")) == 1


def test_admin_shares_sort_before_regular(tmp_path: Path) -> None:
    parse_smbclient_check(_smbclient_listing(), b"", tmp_path, "smbclient")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    first = json.loads(sidecar.splitlines()[0])
    assert first["admin_share"] is True


def test_sidecar_records_tool_id_and_share_metadata(tmp_path: Path) -> None:
    parse_smbclient_check(_smbclient_listing(), b"", tmp_path, "smbclient")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    assert all(r["tool_id"] == "smbclient" for r in records)
    assert any(r["share"] == "Public" for r in records)


def test_workgroup_section_ignored(tmp_path: Path) -> None:
    payload = (
        b"\tWorkgroup            Master\n"
        b"\t---------            -------\n"
        b"\tWORKGROUP            DC01\n"
    )
    assert parse_smbclient_check(payload, b"", tmp_path, "smbclient") == []


def test_findings_are_confirmed(tmp_path: Path) -> None:
    findings = parse_smbclient_check(_smbclient_listing(), b"", tmp_path, "smbclient")
    for finding in findings:
        assert finding.confidence is ConfidenceLevel.CONFIRMED
