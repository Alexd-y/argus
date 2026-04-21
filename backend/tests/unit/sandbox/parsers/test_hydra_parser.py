"""Unit tests for :mod:`src.sandbox.parsers.hydra_parser` (ARG-032).

CRITICAL security gate (C12 contract):
    The cleartext password is NEVER persisted in the sidecar — only the
    canonical ``[REDACTED-PASSWORD]`` marker plus a length hint.
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
from src.sandbox.parsers.hydra_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_hydra,
)


def _hydra_output() -> bytes:
    return (
        b"[22][ssh] host: 10.0.0.1   login: root   password: toor\n"
        b"[443][https-post-form] host: web.example.com   login: admin   password: hunter2\n"
        b"[STATUS] attack finished for 10.0.0.1\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_hydra(b"", b"", tmp_path, "hydra") == []


def test_one_auth_finding_per_credential(tmp_path: Path) -> None:
    findings = parse_hydra(_hydra_output(), b"", tmp_path, "hydra")
    assert len(findings) == 2
    for finding in findings:
        assert finding.category is FindingCategory.AUTH
        assert finding.confidence is ConfidenceLevel.CONFIRMED
        assert finding.ssvc_decision is SSVCDecision.ACT
        assert finding.cvss_v3_score == 9.1


def test_password_redacted_in_sidecar(tmp_path: Path) -> None:
    parse_hydra(_hydra_output(), b"", tmp_path, "hydra")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "toor" not in sidecar
    assert "hunter2" not in sidecar
    assert REDACTED_PASSWORD_MARKER in sidecar


def test_dedup_on_host_service_user(tmp_path: Path) -> None:
    payload = (
        b"[22][ssh] host: 10.0.0.1 login: root password: toor\n"
        b"[22][ssh] host: 10.0.0.1 login: root password: different\n"
    )
    assert len(parse_hydra(payload, b"", tmp_path, "hydra")) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "hydra.txt").write_bytes(
        b"[22][ssh] host: canonical.example.com login: admin password: pwd\n"
    )
    decoy = b"[22][ssh] host: decoy.example.com login: admin password: pwd\n"
    findings = parse_hydra(decoy, b"", tmp_path, "hydra")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example.com" in sidecar


def test_password_length_recorded_in_sidecar(tmp_path: Path) -> None:
    parse_hydra(_hydra_output(), b"", tmp_path, "hydra")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    assert {r["password_length"] for r in records} == {4, 7}


def test_garbage_lines_safely_ignored(tmp_path: Path) -> None:
    payload = b"random log line\n[STATUS] info only\n# comment\n"
    assert parse_hydra(payload, b"", tmp_path, "hydra") == []
