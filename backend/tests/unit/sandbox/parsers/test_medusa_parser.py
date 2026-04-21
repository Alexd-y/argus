"""Unit tests for :mod:`src.sandbox.parsers.medusa_parser` (ARG-032).

CRITICAL security gate (C12 contract):
    The cleartext password is NEVER persisted in the sidecar.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    SSVCDecision,
)
from src.sandbox.parsers._text_base import REDACTED_PASSWORD_MARKER
from src.sandbox.parsers.medusa_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_medusa,
)


def _medusa_output() -> bytes:
    return (
        b"ACCOUNT FOUND: [ssh] Host: 10.0.0.1 User: root Password: toor [SUCCESS]\n"
        b"ACCOUNT FOUND: [ftp] Host: 10.0.0.2 User: anon Password: hunter2 [SUCCESS]\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_medusa(b"", b"", tmp_path, "medusa") == []


def test_one_auth_finding_per_credential(tmp_path: Path) -> None:
    findings = parse_medusa(_medusa_output(), b"", tmp_path, "medusa")
    assert len(findings) == 2
    for finding in findings:
        assert finding.category is FindingCategory.AUTH
        assert finding.confidence is ConfidenceLevel.CONFIRMED
        assert finding.ssvc_decision is SSVCDecision.ACT


def test_password_redacted_in_sidecar(tmp_path: Path) -> None:
    parse_medusa(_medusa_output(), b"", tmp_path, "medusa")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "toor" not in sidecar
    assert "hunter2" not in sidecar
    assert REDACTED_PASSWORD_MARKER in sidecar


def test_dedup_on_host_service_user(tmp_path: Path) -> None:
    payload = (
        b"ACCOUNT FOUND: [ssh] Host: 10.0.0.1 User: root Password: toor [SUCCESS]\n"
        b"ACCOUNT FOUND: [ssh] Host: 10.0.0.1 User: root Password: other [SUCCESS]\n"
    )
    assert len(parse_medusa(payload, b"", tmp_path, "medusa")) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "medusa.txt").write_bytes(
        b"ACCOUNT FOUND: [ssh] Host: canonical.example User: a Password: b [SUCCESS]\n"
    )
    decoy = b"ACCOUNT FOUND: [ssh] Host: decoy.example User: a Password: c [SUCCESS]\n"
    parse_medusa(decoy, b"", tmp_path, "medusa")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example" in sidecar
    assert "decoy.example" not in sidecar


def test_password_length_recorded(tmp_path: Path) -> None:
    parse_medusa(_medusa_output(), b"", tmp_path, "medusa")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    assert {r["password_length"] for r in records} == {4, 7}


def test_garbage_lines_ignored(tmp_path: Path) -> None:
    payload = b"random log\n# header\nfoo bar\n"
    assert parse_medusa(payload, b"", tmp_path, "medusa") == []
