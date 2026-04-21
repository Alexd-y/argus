"""Unit tests for :mod:`src.sandbox.parsers.rpcclient_enum_parser`.

Pinned contracts (Backlog/dev1_md §4.2 — ARG-022):

* ``user:[NAME] rid:[0xRID]`` → INFO LOW (CVSS 3.1, CWE-200) per user.
* ``account[NAME]: name:[X] desc:[Y] attribs:[Z]`` → captured as
  account-detail finding.
* If null-session enumeration succeeds (any users / accounts found),
  one MISCONFIG MEDIUM marker (CVSS 5.3, CWE-200 + CWE-287 + CWE-285)
  is emitted with the domain info.
* Empty / non-recognised input → ``[]``.
* Sidecar JSONL stamped with ``tool_id``.
* Domain info (``Total Users:``, ``Domain Name:``) is captured.
* Dedup on ``(kind, user.lower())``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    FindingCategory,
    SSVCDecision,
)
from src.sandbox.parsers.rpcclient_enum_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_rpcclient_enum,
)


def _rpcclient_output() -> bytes:
    return (
        b"user:[Administrator] rid:[0x1f4]\n"
        b"user:[Guest] rid:[0x1f5]\n"
        b"user:[svc-backup] rid:[0x454]\n"
        b"group:[Domain Admins] rid:[0x200]\n"
        b"group:[Domain Users] rid:[0x201]\n"
        b"Domain Name: CONTOSO\n"
        b"Domain Server: DC01\n"
        b"Total Users: 3\n"
        b"Total Groups: 2\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_rpcclient_enum(b"", b"", tmp_path, "rpcclient_enum") == []


def test_garbage_input_returns_no_findings(tmp_path: Path) -> None:
    assert (
        parse_rpcclient_enum(
            b"random text\nno markers\n", b"", tmp_path, "rpcclient_enum"
        )
        == []
    )


def test_happy_path_emits_users_plus_null_session_marker(tmp_path: Path) -> None:
    findings = parse_rpcclient_enum(
        _rpcclient_output(), b"", tmp_path, "rpcclient_enum"
    )
    assert len(findings) == 4


def test_null_session_finding_is_misconfig_medium(tmp_path: Path) -> None:
    findings = parse_rpcclient_enum(
        _rpcclient_output(), b"", tmp_path, "rpcclient_enum"
    )
    null_findings = [f for f in findings if f.cvss_v3_score == 5.3]
    assert null_findings
    finding = null_findings[0]
    assert finding.category is FindingCategory.MISCONFIG
    assert finding.ssvc_decision is SSVCDecision.ATTEND


def test_user_findings_are_info_low(tmp_path: Path) -> None:
    findings = parse_rpcclient_enum(
        _rpcclient_output(), b"", tmp_path, "rpcclient_enum"
    )
    user_findings = [f for f in findings if f.cvss_v3_score == 3.1]
    assert user_findings
    for finding in user_findings:
        assert finding.category is FindingCategory.INFO


def test_account_detail_blocks_are_recognised(tmp_path: Path) -> None:
    payload = (
        b"user:[Administrator] rid:[0x1f4]\n"
        b"account[Administrator]: name:[Administrator] "
        b"desc:[Built-in account] attribs:[Account Disabled]\n"
    )
    findings = parse_rpcclient_enum(payload, b"", tmp_path, "rpcclient_enum")
    assert len(findings) >= 2


def test_sidecar_records_domain_info(tmp_path: Path) -> None:
    parse_rpcclient_enum(_rpcclient_output(), b"", tmp_path, "rpcclient_enum")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    domain_records = [
        r for r in records if r.get("domain_info", {}).get("Domain Name") == "CONTOSO"
    ]
    assert domain_records
    assert all(r["tool_id"] == "rpcclient_enum" for r in records)


def test_dedup_collapses_duplicate_users(tmp_path: Path) -> None:
    payload = (
        b"user:[admin] rid:[0x1f4]\n"
        b"user:[admin] rid:[0x1f4]\n"
        b"user:[admin] rid:[0x1f4]\n"
    )
    findings = parse_rpcclient_enum(payload, b"", tmp_path, "rpcclient_enum")
    user_findings = [f for f in findings if f.cvss_v3_score == 3.1]
    assert len(user_findings) == 1


def test_no_users_no_null_session_marker(tmp_path: Path) -> None:
    payload = b"Domain Name: CONTOSO\nTotal Users: 0\n"
    findings = parse_rpcclient_enum(payload, b"", tmp_path, "rpcclient_enum")
    assert findings == []


def test_null_session_marker_sorts_first(tmp_path: Path) -> None:
    parse_rpcclient_enum(_rpcclient_output(), b"", tmp_path, "rpcclient_enum")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    first = json.loads(sidecar.splitlines()[0])
    assert first.get("null_session") is True


def test_decimal_rid_values_are_recognised(tmp_path: Path) -> None:
    payload = b"user:[admin] rid:[500]\n"
    findings = parse_rpcclient_enum(payload, b"", tmp_path, "rpcclient_enum")
    assert any(f.cvss_v3_score == 3.1 for f in findings)
