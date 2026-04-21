"""Unit tests for :mod:`src.sandbox.parsers.enum4linux_ng_parser`.

Pinned contracts (Backlog/dev1_md §4.2 — ARG-022):

* ``=== <divider> ===`` + ``| <title> |`` produces named sections.
* ``[+] key ......... value`` lines are captured into the section
  ``fields`` dict.
* ``[+] Found user/group 'name' (RID: NNN)`` is captured into a
  per-section ``members`` list.
* ``Null sessions allowed`` / ``Anonymous bind allowed`` markers
  escalate to MISCONFIG MEDIUM (CVSS 6.5).
* Other sections → INFO LOW (CVSS 3.7).
* Sidecar JSONL stamped with ``tool_id``.
* Empty input returns ``[]``.
* Dedup on ``(kind, section.lower())``.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    SSVCDecision,
)
from src.sandbox.parsers.enum4linux_ng_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_enum4linux_ng,
)


def _enum4linux_output() -> bytes:
    return (
        b"==========================\n"
        b"|    Target Information   |\n"
        b"==========================\n"
        b"[+] Target ........... 10.0.0.42\n"
        b"[+] Username ......... 'guest'\n"
        b"\n"
        b"==============================\n"
        b"|    Sessions on 10.0.0.42   |\n"
        b"==============================\n"
        b"[+] Null sessions allowed: rpc bind succeeded for IPC$\n"
        b"\n"
        b"================================\n"
        b"|    Users via RPC on 10.0.0.42|\n"
        b"================================\n"
        b"[+] Found user 'administrator' (RID: 500)\n"
        b"[+] Found user 'guest' (RID: 501)\n"
        b"[+] Found user 'krbtgt' (RID: 502)\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_enum4linux_ng(b"", b"", tmp_path, "enum4linux_ng") == []


def test_garbage_input_returns_no_findings(tmp_path: Path) -> None:
    assert (
        parse_enum4linux_ng(
            b"random text without sections\n", b"", tmp_path, "enum4linux_ng"
        )
        == []
    )


def test_happy_path_emits_findings_per_section(tmp_path: Path) -> None:
    findings = parse_enum4linux_ng(_enum4linux_output(), b"", tmp_path, "enum4linux_ng")
    assert len(findings) >= 2


def test_null_session_section_escalates_severity(tmp_path: Path) -> None:
    findings = parse_enum4linux_ng(_enum4linux_output(), b"", tmp_path, "enum4linux_ng")
    null_findings = [f for f in findings if f.cvss_v3_score == 6.5]
    assert null_findings
    finding = null_findings[0]
    assert finding.category is FindingCategory.MISCONFIG
    assert finding.ssvc_decision is SSVCDecision.ATTEND


def test_regular_section_is_info_low(tmp_path: Path) -> None:
    payload = (
        b"==========================\n"
        b"|    Target Information   |\n"
        b"==========================\n"
        b"[+] Target ........... 10.0.0.42\n"
    )
    findings = parse_enum4linux_ng(payload, b"", tmp_path, "enum4linux_ng")
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert finding.cvss_v3_score == 3.7


def test_sidecar_captures_section_fields_and_members(tmp_path: Path) -> None:
    parse_enum4linux_ng(_enum4linux_output(), b"", tmp_path, "enum4linux_ng")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    assert all(r["tool_id"] == "enum4linux_ng" for r in records)
    user_section = next(
        (r for r in records if r.get("members")),
        None,
    )
    assert user_section is not None
    assert any("administrator" in m for m in user_section["members"])


def test_dedup_collapses_repeated_sections(tmp_path: Path) -> None:
    base = _enum4linux_output()
    findings = parse_enum4linux_ng(base + base, b"", tmp_path, "enum4linux_ng")
    findings_single = parse_enum4linux_ng(base, b"", tmp_path, "enum4linux_ng")
    assert len(findings) == len(findings_single)


def test_anonymous_bind_marker_escalates(tmp_path: Path) -> None:
    payload = (
        b"==========================\n"
        b"|    Bind   |\n"
        b"==========================\n"
        b"[+] Anonymous bind allowed: yes\n"
    )
    findings = parse_enum4linux_ng(payload, b"", tmp_path, "enum4linux_ng")
    assert findings[0].category is FindingCategory.MISCONFIG


def test_null_session_sorts_first(tmp_path: Path) -> None:
    parse_enum4linux_ng(_enum4linux_output(), b"", tmp_path, "enum4linux_ng")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    first = json.loads(sidecar.splitlines()[0])
    assert first.get("null_session") is True


def test_findings_confidence_for_null_session_is_confirmed(tmp_path: Path) -> None:
    findings = parse_enum4linux_ng(_enum4linux_output(), b"", tmp_path, "enum4linux_ng")
    null_findings = [f for f in findings if f.cvss_v3_score == 6.5]
    assert null_findings[0].confidence is ConfidenceLevel.CONFIRMED
