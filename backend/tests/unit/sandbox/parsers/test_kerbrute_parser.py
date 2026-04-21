"""Unit tests for :mod:`src.sandbox.parsers.kerbrute_parser`.

Pinned contracts (Backlog/dev1_md §4.12 — ARG-022):

* ``[+] VALID USERNAME: <user>@<domain>`` → AUTH finding (CVSS 5.3).
* ``[+] VALID USERNAME (NO PREAUTH): <user>@<domain>`` → AUTH
  finding (CVSS 8.8, CWE-287 escalates to AS-REP roasting).
* Dedup on ``(account, no_preauth_flag)`` — running kerbrute twice
  emits one finding per unique account / no-preauth combination.
* Sort priority: NO PREAUTH first, then alpha by domain → user.
* Sidecar JSONL stamped with ``tool_id``.
* Empty input / no valid lines → ``[]``.
* Account names without ``@`` are skipped defensively.
* Cap honoured at 5_000 records.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    SSVCDecision,
)
from src.sandbox.parsers.kerbrute_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_kerbrute,
)


def _kerbrute_output() -> bytes:
    return (
        b"2026/04/19 12:34:56 >  [+] VALID USERNAME:    administrator@contoso.local\n"
        b"2026/04/19 12:34:56 >  [+] VALID USERNAME:    svc-backup@contoso.local\n"
        b"2026/04/19 12:34:57 >  [+] VALID USERNAME (NO PREAUTH):  legacy@contoso.local\n"
        b"2026/04/19 12:34:58 >  Done! Tested 100 usernames (3 valid)\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_kerbrute(b"", b"", tmp_path, "kerbrute") == []


def test_happy_path_emits_finding_per_account(tmp_path: Path) -> None:
    findings = parse_kerbrute(_kerbrute_output(), b"", tmp_path, "kerbrute")
    assert len(findings) == 3
    for finding in findings:
        assert finding.category is FindingCategory.AUTH
        assert finding.confidence is ConfidenceLevel.CONFIRMED


def test_no_preauth_account_emits_high_severity(tmp_path: Path) -> None:
    payload = b"[+] VALID USERNAME (NO PREAUTH): legacy@contoso.local\n"
    findings = parse_kerbrute(payload, b"", tmp_path, "kerbrute")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.cvss_v3_score == 8.8
    assert 287 in finding.cwe
    assert finding.ssvc_decision is SSVCDecision.ATTEND


def test_regular_valid_user_uses_lower_severity(tmp_path: Path) -> None:
    payload = b"[+] VALID USERNAME:    administrator@contoso.local\n"
    findings = parse_kerbrute(payload, b"", tmp_path, "kerbrute")
    assert findings[0].cvss_v3_score == 5.3


def test_dedup_collapses_duplicate_account(tmp_path: Path) -> None:
    payload = (
        b"[+] VALID USERNAME: foo@contoso.local\n"
        b"[+] VALID USERNAME: foo@contoso.local\n"
        b"[+] VALID USERNAME: foo@contoso.local\n"
    )
    assert len(parse_kerbrute(payload, b"", tmp_path, "kerbrute")) == 1


def test_no_preauth_and_regular_for_same_account_are_distinct(tmp_path: Path) -> None:
    payload = (
        b"[+] VALID USERNAME: foo@contoso.local\n"
        b"[+] VALID USERNAME (NO PREAUTH): foo@contoso.local\n"
    )
    assert len(parse_kerbrute(payload, b"", tmp_path, "kerbrute")) == 2


def test_lines_without_at_sign_skipped(tmp_path: Path) -> None:
    payload = b"[+] VALID USERNAME: malformed_no_at\n"
    assert parse_kerbrute(payload, b"", tmp_path, "kerbrute") == []


def test_sidecar_records_account_and_tool_id(tmp_path: Path) -> None:
    parse_kerbrute(_kerbrute_output(), b"", tmp_path, "kerbrute")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    assert len(records) == 3
    assert all(r["tool_id"] == "kerbrute" for r in records)
    assert any(r["no_preauth"] for r in records)


def test_no_preauth_records_sort_first(tmp_path: Path) -> None:
    payload = (
        b"[+] VALID USERNAME: zzz@contoso.local\n"
        b"[+] VALID USERNAME (NO PREAUTH): aaa@contoso.local\n"
    )
    parse_kerbrute(payload, b"", tmp_path, "kerbrute")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    first = json.loads(sidecar.splitlines()[0])
    assert first["no_preauth"] is True


def test_garbage_lines_safely_ignored(tmp_path: Path) -> None:
    payload = b"random garbage\n# comment\n#another\n"
    assert parse_kerbrute(payload, b"", tmp_path, "kerbrute") == []
