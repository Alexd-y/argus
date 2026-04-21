"""Unit tests for :mod:`src.sandbox.parsers.responder_parser` (ARG-032).

CRITICAL security gate (C12 contract):
    The captured NTLM hash blob is masked BEFORE the FindingDTO is built.
    The raw hash bytes never traverse the Pydantic validator and never
    appear in the sidecar.
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
from src.sandbox.parsers.responder_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_responder,
)

_NTLM_HASH = (
    "bob::CORP:1122334455667788:"
    "ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789:"
    "01010000000000000123456789ABCDEF"
)


def _responder_log() -> bytes:
    return (
        b"[SMB] NTLMv2-SSP Client   : 10.0.0.10\n"
        b"[SMB] NTLMv2-SSP Username : CORP\\bob\n"
        + f"[SMB] NTLMv2-SSP Hash     : {_NTLM_HASH}\n".encode()
        + b"[HTTP] NTLMv1 Client    : 10.0.0.20\n"
        b"[HTTP] NTLMv1 Username  : alice\n"
        b"[HTTP] NTLMv1 Hash      : alice::CORP:0011223344556677:ABCD:EFGH\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_responder(b"", b"", tmp_path, "responder") == []


def test_one_auth_finding_per_capture(tmp_path: Path) -> None:
    findings = parse_responder(_responder_log(), b"", tmp_path, "responder")
    assert len(findings) == 2
    for finding in findings:
        assert finding.category is FindingCategory.AUTH
        assert finding.confidence is ConfidenceLevel.CONFIRMED
        assert finding.ssvc_decision is SSVCDecision.ACT
        assert finding.cvss_v3_score == 8.8


def test_ntlm_hash_redacted_in_sidecar(tmp_path: Path) -> None:
    parse_responder(_responder_log(), b"", tmp_path, "responder")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert _NTLM_HASH not in sidecar
    assert "ABCDEF0123456789" not in sidecar
    assert REDACTED_NT_HASH_MARKER in sidecar


def test_username_and_domain_preserved(tmp_path: Path) -> None:
    parse_responder(_responder_log(), b"", tmp_path, "responder")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    domains = {r["domain"] for r in records}
    users = {r["username"] for r in records}
    assert "CORP" in domains
    assert "bob" in users
    assert "alice" in users


def test_dedup_collapses_repeated_capture(tmp_path: Path) -> None:
    log = (
        b"[SMB] NTLMv2-SSP Client   : 10.0.0.10\n"
        b"[SMB] NTLMv2-SSP Username : CORP\\bob\n"
        b"[SMB] NTLMv2-SSP Hash     : bob::CORP:11223344:ABC:DEF\n"
        b"[SMB] NTLMv2-SSP Client   : 10.0.0.10\n"
        b"[SMB] NTLMv2-SSP Username : CORP\\bob\n"
        b"[SMB] NTLMv2-SSP Hash     : bob::CORP:11223344:ABC:DEF\n"
    )
    assert len(parse_responder(log, b"", tmp_path, "responder")) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "responder.log").write_bytes(
        b"[SMB] NTLMv2-SSP Client   : 10.0.0.99\n"
        b"[SMB] NTLMv2-SSP Username : CORP\\admin\n"
        b"[SMB] NTLMv2-SSP Hash     : admin::CORP:11:AA:BB\n"
    )
    decoy = b"[SMB] NTLMv2-SSP Client   : 10.0.0.1\n"
    parse_responder(decoy, b"", tmp_path, "responder")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "10.0.0.99" in sidecar
    assert "10.0.0.1" not in sidecar


def test_sidecar_records_proto_and_ntlm_version(tmp_path: Path) -> None:
    parse_responder(_responder_log(), b"", tmp_path, "responder")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    protos = {r["proto"] for r in records}
    versions = {r["ntlm_version"] for r in records}
    assert protos == {"SMB", "HTTP"}
    assert versions == {"NTLMv2", "NTLMv1"}
