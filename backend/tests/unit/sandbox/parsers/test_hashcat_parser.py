"""Unit tests for :mod:`src.sandbox.parsers.hashcat_parser` (ARG-032).

CRITICAL security gates (C12 contract):
    * Both the hash bytes AND the cracked plaintext are masked before
      the FindingDTO is built.
    * Only a length hint and a 12-char fingerprint survive.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    SSVCDecision,
)
from src.sandbox.parsers._text_base import (
    REDACTED_HASH_MARKER,
    REDACTED_PASSWORD_MARKER,
)
from src.sandbox.parsers.hashcat_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_hashcat,
)

# Realistic NTLM hash (32 hex chars).
_NTLM_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
# bcrypt hash.
_BCRYPT = "$2b$12$abcdefghijklmnopqrstuvabcdefghijklmnopqrstuvabcdefghi"
# SHA-256.
_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _hashcat_output() -> bytes:
    return (
        f"{_NTLM_HASH}:Welcome1\n{_BCRYPT}:hunter2\n{_SHA256}:salt:plaintext\n"
    ).encode()


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_hashcat(b"", b"", tmp_path, "hashcat") == []


def test_one_finding_per_unique_hash(tmp_path: Path) -> None:
    findings = parse_hashcat(_hashcat_output(), b"", tmp_path, "hashcat")
    assert len(findings) == 3
    for finding in findings:
        assert finding.category is FindingCategory.AUTH
        assert finding.confidence is ConfidenceLevel.CONFIRMED
        assert finding.ssvc_decision is SSVCDecision.ACT


def test_hash_value_redacted_in_sidecar(tmp_path: Path) -> None:
    parse_hashcat(_hashcat_output(), b"", tmp_path, "hashcat")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert _NTLM_HASH not in sidecar
    assert _BCRYPT not in sidecar
    assert _SHA256 not in sidecar
    assert REDACTED_HASH_MARKER in sidecar


def test_plaintext_redacted_in_sidecar(tmp_path: Path) -> None:
    parse_hashcat(_hashcat_output(), b"", tmp_path, "hashcat")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "Welcome1" not in sidecar
    assert "hunter2" not in sidecar
    assert "plaintext" not in sidecar
    assert REDACTED_PASSWORD_MARKER in sidecar


def test_hash_kind_classified_correctly(tmp_path: Path) -> None:
    parse_hashcat(_hashcat_output(), b"", tmp_path, "hashcat")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    kinds = {r["hash_kind"] for r in records}
    assert kinds == {"ntlm", "bcrypt", "sha256"}


def test_dedup_collapses_repeated_hash(tmp_path: Path) -> None:
    payload = f"{_NTLM_HASH}:foo\n{_NTLM_HASH}:bar\n".encode()
    assert len(parse_hashcat(payload, b"", tmp_path, "hashcat")) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "cracked.txt").write_bytes(f"{_NTLM_HASH}:canonical\n".encode())
    decoy = f"{_BCRYPT}:decoy\n".encode()
    findings = parse_hashcat(decoy, b"", tmp_path, "hashcat")
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    record = json.loads(sidecar.splitlines()[0])
    assert record["hash_kind"] == "ntlm"


def test_lines_without_colon_skipped(tmp_path: Path) -> None:
    payload = b"# comment\nnonsense_no_colon\n\n"
    assert parse_hashcat(payload, b"", tmp_path, "hashcat") == []
