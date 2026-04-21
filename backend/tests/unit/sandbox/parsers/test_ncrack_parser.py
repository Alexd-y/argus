"""Unit tests for :mod:`src.sandbox.parsers.ncrack_parser` (ARG-032).

CRITICAL security gate (C12 contract):
    Cleartext passwords are redacted before any FindingDTO is built.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers._text_base import REDACTED_PASSWORD_MARKER
from src.sandbox.parsers.ncrack_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_ncrack,
)


def _ncrack_output() -> bytes:
    return (
        b"Discovered credentials on ssh://10.0.0.1:22\n"
        b"    10.0.0.1 22/tcp ssh: 'root' 'toor'\n"
        b"    10.0.0.1 22/tcp ssh: 'admin' 'hunter2'\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_ncrack(b"", b"", tmp_path, "ncrack") == []


def test_one_finding_per_credential(tmp_path: Path) -> None:
    findings = parse_ncrack(_ncrack_output(), b"", tmp_path, "ncrack")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.AUTH for f in findings)


def test_password_redacted_in_sidecar(tmp_path: Path) -> None:
    parse_ncrack(_ncrack_output(), b"", tmp_path, "ncrack")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "toor" not in sidecar
    assert "hunter2" not in sidecar
    assert REDACTED_PASSWORD_MARKER in sidecar


def test_dedup_on_host_service_user(tmp_path: Path) -> None:
    payload = b"10.0.0.1 22/tcp ssh: 'root' 'a'\n10.0.0.1 22/tcp ssh: 'root' 'b'\n"
    assert len(parse_ncrack(payload, b"", tmp_path, "ncrack")) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "ncrack.txt").write_bytes(
        b"canonical.example 22/tcp ssh: 'admin' 'pwd'\n"
    )
    decoy = b"decoy.example 22/tcp ssh: 'admin' 'pwd'\n"
    parse_ncrack(decoy, b"", tmp_path, "ncrack")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example" in sidecar


def test_port_and_proto_recorded(tmp_path: Path) -> None:
    parse_ncrack(_ncrack_output(), b"", tmp_path, "ncrack")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["port"] == "22"
    assert record["proto"] == "tcp"
    assert record["service"] == "ssh"


def test_user_only_lines_skipped(tmp_path: Path) -> None:
    payload = b"10.0.0.1 22/tcp ssh: '' ''\n"
    assert parse_ncrack(payload, b"", tmp_path, "ncrack") == []
