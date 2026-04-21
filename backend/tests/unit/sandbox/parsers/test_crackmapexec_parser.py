"""Unit tests for :mod:`src.sandbox.parsers.crackmapexec_parser` (ARG-032).

CRITICAL security gates (C12 contract):
    * Cleartext passwords are redacted before any FindingDTO is built.
    * NTLM ``LM:NT`` hash pairs (32:32 hex) are redacted before sidecar.
    * The raw 32-char hash bytes never appear in the sidecar output.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers._text_base import REDACTED_PASSWORD_MARKER
from src.sandbox.parsers.crackmapexec_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_crackmapexec,
)

_NT_HASH_PAIR = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def _cme_output() -> bytes:
    return (
        b"SMB         10.0.0.1  445  DC01      [+] CORP\\admin:Password123 (Pwn3d!)\n"
        + f"SMB         10.0.0.1  445  DC01      [+] CORP\\svc_sql:{_NT_HASH_PAIR}\n".encode()
        + b"SMB         10.0.0.1  445  DC01      [-] CORP\\guest:guest STATUS_LOGON_FAILURE\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_crackmapexec(b"", b"", tmp_path, "crackmapexec") == []


def test_one_finding_per_credential(tmp_path: Path) -> None:
    findings = parse_crackmapexec(_cme_output(), b"", tmp_path, "crackmapexec")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.AUTH for f in findings)


def test_password_redacted_in_sidecar(tmp_path: Path) -> None:
    parse_crackmapexec(_cme_output(), b"", tmp_path, "crackmapexec")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "Password123" not in sidecar
    assert REDACTED_PASSWORD_MARKER in sidecar


def test_ntlm_hash_pair_redacted_in_sidecar(tmp_path: Path) -> None:
    parse_crackmapexec(_cme_output(), b"", tmp_path, "crackmapexec")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert _NT_HASH_PAIR not in sidecar
    assert "aad3b435b51404eeaad3b435b51404ee" not in sidecar
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in sidecar


def test_credential_kind_marked(tmp_path: Path) -> None:
    parse_crackmapexec(_cme_output(), b"", tmp_path, "crackmapexec")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    kinds = {r["credential_kind"] for r in records}
    assert kinds == {"cleartext_password", "ntlm_hash_pair"}


def test_pwn3d_marker_recorded(tmp_path: Path) -> None:
    parse_crackmapexec(_cme_output(), b"", tmp_path, "crackmapexec")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    assert any(r["pwn3d"] == "true" for r in records)


def test_dedup_collapses_repeated_entries(tmp_path: Path) -> None:
    payload = (
        b"SMB 10.0.0.1 445 DC [+] CORP\\admin:pwd1\n"
        b"SMB 10.0.0.1 445 DC [+] CORP\\admin:pwd2\n"
    )
    assert len(parse_crackmapexec(payload, b"", tmp_path, "crackmapexec")) == 1


def test_failed_attempts_skipped(tmp_path: Path) -> None:
    payload = b"SMB 10.0.0.1 445 DC [-] CORP\\guest:guest STATUS_LOGON_FAILURE\n"
    assert parse_crackmapexec(payload, b"", tmp_path, "crackmapexec") == []
