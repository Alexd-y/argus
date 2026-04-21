"""Unit tests for :mod:`src.sandbox.parsers.evil_winrm_parser`.

Pinned contracts (Backlog/dev1_md §4.12 — ARG-022):

* Captures host (banner), exit code (``Exiting with code N``), the
  last operator command (text after the final ``*Evil-WinRM* PS …>``
  prompt) and up to 5 error lines.
* Empty / whitespace stdout returns ``[]`` and writes no sidecar.
* Single INFO post-exploitation marker per session — severity is the
  heartbeat-class sentinel (CVSS 0.0, ConfidenceLevel.SUSPECTED).
* Sidecar JSONL is stamped with ``tool_id``.
* Strips ANSI escape sequences and ``\\r`` artefacts when summarising
  the transcript.
* Hash-shaped strings leaking into PowerShell output are redacted via
  the shared ``redact_hash_string`` helper.
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
from src.sandbox.parsers.evil_winrm_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_evil_winrm,
)


def _transcript() -> bytes:
    return (
        b"Evil-WinRM shell v3.5\n"
        b"Info: Establishing connection to remote endpoint: dc01.contoso.local\n"
        b"*Evil-WinRM* PS C:\\Users\\Administrator> whoami\n"
        b"contoso\\administrator\n"
        b"*Evil-WinRM* PS C:\\Users\\Administrator> hostname\n"
        b"DC01\n"
        b"*Evil-WinRM* PS C:\\Users\\Administrator> exit\n"
        b"Info: Exiting with code 0\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_evil_winrm(b"", b"", tmp_path, "evil_winrm") == []


def test_pure_whitespace_returns_no_findings(tmp_path: Path) -> None:
    assert parse_evil_winrm(b"   \n  \n", b"", tmp_path, "evil_winrm") == []


def test_happy_path_emits_single_info_finding(tmp_path: Path) -> None:
    findings = parse_evil_winrm(_transcript(), b"", tmp_path, "evil_winrm")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category is FindingCategory.INFO
    assert finding.confidence is ConfidenceLevel.SUSPECTED
    assert finding.cvss_v3_score == 0.0
    assert finding.ssvc_decision is SSVCDecision.TRACK


def test_sidecar_captures_host_exit_and_last_command(tmp_path: Path) -> None:
    parse_evil_winrm(_transcript(), b"", tmp_path, "evil_winrm")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["tool_id"] == "evil_winrm"
    assert record["host"] == "dc01.contoso.local"
    assert record["exit_code"] == 0
    assert record["last_command"] in {"hostname", "exit"}


def test_unfinished_session_uses_minus_one_exit_code(tmp_path: Path) -> None:
    payload = (
        b"Info: Establishing connection to remote endpoint: dc01.contoso.local\n"
        b"*Evil-WinRM* PS C:\\Users> whoami\n"
        b"contoso\\administrator\n"
    )
    parse_evil_winrm(payload, b"", tmp_path, "evil_winrm")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["exit_code"] == -1


def test_error_lines_are_captured_up_to_cap(tmp_path: Path) -> None:
    payload = (
        b"Info: Establishing connection to remote endpoint: dc01.contoso.local\n"
        b"Error: connection refused\n"
        b"FATAL: handshake timeout\n"
        b"*Evil-WinRM* PS C:\\Users> whoami\n"
        b"Info: Exiting with code 2\n"
    )
    parse_evil_winrm(payload, b"", tmp_path, "evil_winrm")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert "errors" in record
    assert len(record["errors"]) == 2


def test_ansi_sequences_stripped_from_transcript(tmp_path: Path) -> None:
    payload = (
        b"Info: Establishing connection to remote endpoint: dc01.contoso.local\n"
        b"\x1b[32m*Evil-WinRM* PS C:\\Users>\x1b[0m whoami\n"
        b"contoso\\administrator\n"
        b"Info: Exiting with code 0\n"
    )
    parse_evil_winrm(payload, b"", tmp_path, "evil_winrm")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record.get("last_command") == "whoami"


def test_leaked_hash_in_command_is_redacted(tmp_path: Path) -> None:
    payload = (
        b"Info: Establishing connection to remote endpoint: dc01.contoso.local\n"
        b"*Evil-WinRM* PS C:\\Users> echo aad3b435b51404eeaad3b435b51404ee:"
        b"31d6cfe0d16ae931b73c59d7e0c089c0\n"
        b"Info: Exiting with code 0\n"
    )
    parse_evil_winrm(payload, b"", tmp_path, "evil_winrm")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "aad3b435b51404eeaad3b435b51404ee" not in sidecar
    assert REDACTED_NT_HASH_MARKER in sidecar


def test_no_recognisable_markers_yields_no_finding(tmp_path: Path) -> None:
    findings = parse_evil_winrm(
        b"random\nlines\nwith\nno\nmarkers\n", b"", tmp_path, "evil_winrm"
    )
    assert findings == []


def test_truncates_extremely_long_command(tmp_path: Path) -> None:
    long_cmd = b"a" * 1024
    payload = (
        b"Info: Establishing connection to remote endpoint: dc01.contoso.local\n"
        b"*Evil-WinRM* PS C:\\Users> " + long_cmd + b"\n"
        b"Info: Exiting with code 0\n"
    )
    parse_evil_winrm(payload, b"", tmp_path, "evil_winrm")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert "[truncated]" in record["last_command"]
