"""Unit tests for :mod:`src.sandbox.parsers.ldapsearch_parser`.

Pinned contracts (Backlog/dev1_md §4.17 — ARG-022):

* One :class:`FindingDTO` per ``dn:`` LDIF block.
* High-value group membership (``Domain Admins`` / ``Enterprise
  Admins`` / ``Schema Admins``) → AUTH MEDIUM (CVSS 5.3, CWE-269 +
  CWE-200 + CWE-287).
* Non-privileged accounts → INFO LOW (CVSS 3.7, CWE-200).
* Empty / pure-comment LDIF returns ``[]``.
* Sidecar JSONL stamped with ``tool_id``, captures DN + objectClass +
  memberOf + attributes (with hash-shaped values redacted).
* Continuation lines (LDIF folded values) are merged into the
  previous attribute value.
* Dedup on ``(kind, dn.lower())``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    SSVCDecision,
)
from src.sandbox.parsers._text_base import REDACTED_NT_HASH_MARKER
from src.sandbox.parsers.ldapsearch_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_ldapsearch,
)


def _ldif_admin() -> bytes:
    return (
        b"dn: CN=Administrator,CN=Users,DC=contoso,DC=local\n"
        b"objectClass: top\n"
        b"objectClass: user\n"
        b"cn: Administrator\n"
        b"memberOf: CN=Domain Admins,CN=Users,DC=contoso,DC=local\n"
        b"memberOf: CN=Enterprise Admins,CN=Users,DC=contoso,DC=local\n"
        b"sAMAccountName: Administrator\n"
        b"\n"
    )


def _ldif_regular() -> bytes:
    return (
        b"dn: CN=jdoe,OU=Employees,DC=contoso,DC=local\n"
        b"objectClass: top\n"
        b"objectClass: user\n"
        b"cn: John Doe\n"
        b"memberOf: CN=Domain Users,CN=Users,DC=contoso,DC=local\n"
        b"sAMAccountName: jdoe\n"
        b"\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_ldapsearch(b"", b"", tmp_path, "ldapsearch") == []


def test_pure_comments_yield_no_findings(tmp_path: Path) -> None:
    payload = b"# extended LDIF\n# LDAPv3\n# nothing here\n"
    assert parse_ldapsearch(payload, b"", tmp_path, "ldapsearch") == []


def test_happy_path_emits_one_finding_per_dn(tmp_path: Path) -> None:
    findings = parse_ldapsearch(
        _ldif_admin() + _ldif_regular(), b"", tmp_path, "ldapsearch"
    )
    assert len(findings) == 2


def test_privileged_account_emits_auth_medium(tmp_path: Path) -> None:
    findings = parse_ldapsearch(_ldif_admin(), b"", tmp_path, "ldapsearch")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.AUTH
    assert finding.cvss_v3_score == 5.3
    assert 269 in finding.cwe
    assert finding.ssvc_decision is SSVCDecision.ATTEND


def test_regular_account_emits_info_low(tmp_path: Path) -> None:
    findings = parse_ldapsearch(_ldif_regular(), b"", tmp_path, "ldapsearch")
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert finding.cvss_v3_score == 3.7
    assert finding.confidence is ConfidenceLevel.LIKELY


def test_sidecar_records_dn_and_object_classes(tmp_path: Path) -> None:
    parse_ldapsearch(_ldif_admin(), b"", tmp_path, "ldapsearch")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "ldapsearch"
    assert record["dn"].startswith("CN=Administrator")
    assert "user" in record["object_classes"]
    assert record["privileged"] is True


def test_dedup_collapses_same_dn(tmp_path: Path) -> None:
    findings = parse_ldapsearch(
        _ldif_admin() + _ldif_admin() + _ldif_admin(),
        b"",
        tmp_path,
        "ldapsearch",
    )
    assert len(findings) == 1


def test_privileged_record_sorts_first(tmp_path: Path) -> None:
    payload = _ldif_regular() + _ldif_admin()
    parse_ldapsearch(payload, b"", tmp_path, "ldapsearch")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    first = json.loads(sidecar.splitlines()[0])
    assert first["privileged"] is True


def test_hash_shaped_attribute_value_is_redacted(tmp_path: Path) -> None:
    payload = (
        b"dn: CN=foo,DC=contoso,DC=local\n"
        b"objectClass: user\n"
        b"unicodePwd: aad3b435b51404eeaad3b435b51404ee\n"
        b"\n"
    )
    parse_ldapsearch(payload, b"", tmp_path, "ldapsearch")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "aad3b435b51404eeaad3b435b51404ee" not in sidecar
    assert REDACTED_NT_HASH_MARKER in sidecar


def test_continuation_lines_merged_into_value(tmp_path: Path) -> None:
    payload = (
        b"dn: CN=foo,DC=contoso,DC=local\n"
        b"objectClass: user\n"
        b"description: long\n"
        b"  description value continues here\n"
        b"\n"
    )
    findings = parse_ldapsearch(payload, b"", tmp_path, "ldapsearch")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "description value continues here" in sidecar


def test_block_without_dn_is_skipped(tmp_path: Path) -> None:
    payload = b"objectClass: orphan\ncn: noDN\n\n"
    assert parse_ldapsearch(payload, b"", tmp_path, "ldapsearch") == []
