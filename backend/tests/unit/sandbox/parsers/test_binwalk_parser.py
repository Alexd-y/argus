"""Unit tests for :mod:`src.sandbox.parsers.binwalk_parser` (ARG-032).

Pinned contracts:

* Recognised signature rows ⇒ INFO findings.
* ``RSA private key`` / ``OpenSSH private key`` rows ⇒ SECRET_LEAK
  (CVSS 7.8, CWE-321/798).
* Memory addresses (``0x...``) are scrubbed before sidecar persistence.
* Header rows (``DECIMAL``, ``----``) are skipped.
"""

from __future__ import annotations

from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.binwalk_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_binwalk,
)


def _binwalk_log() -> bytes:
    return (
        b"DECIMAL       HEXADECIMAL     DESCRIPTION\n"
        b"--------------------------------------------------------------------\n"
        b"0             0x0             ELF, 64-bit LSB executable\n"
        b'16384         0x4000          Linux kernel version "5.15.0"\n'
        b"65536         0xdeadbeef10    RSA private key\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_binwalk(b"", b"", tmp_path, "binwalk") == []


def test_signature_rows_emit_info_findings(tmp_path: Path) -> None:
    findings = parse_binwalk(_binwalk_log(), b"", tmp_path, "binwalk")
    info = [f for f in findings if f.category is FindingCategory.INFO]
    secret = [f for f in findings if f.category is FindingCategory.SECRET_LEAK]
    assert len(info) == 2
    assert len(secret) == 1


def test_rsa_private_key_escalates_to_secret_leak(tmp_path: Path) -> None:
    findings = parse_binwalk(_binwalk_log(), b"", tmp_path, "binwalk")
    secrets = [f for f in findings if f.category is FindingCategory.SECRET_LEAK]
    assert secrets[0].cvss_v3_score == 7.8
    assert 321 in secrets[0].cwe and 798 in secrets[0].cwe


def test_memory_addresses_scrubbed_in_sidecar(tmp_path: Path) -> None:
    parse_binwalk(_binwalk_log(), b"", tmp_path, "binwalk")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "0xdeadbeef10" not in sidecar


def test_header_rows_skipped(tmp_path: Path) -> None:
    payload = (
        b"DECIMAL       HEXADECIMAL     DESCRIPTION\n"
        b"--------------------------------------------------------------------\n"
    )
    assert parse_binwalk(payload, b"", tmp_path, "binwalk") == []


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "binwalk.log").write_bytes(
        b"0             0x0             OpenSSH private key\n"
    )
    decoy = b"0             0x0             ELF, 64-bit LSB executable\n"
    findings = parse_binwalk(decoy, b"", tmp_path, "binwalk")
    assert any(f.category is FindingCategory.SECRET_LEAK for f in findings)


def test_dedup_collapses_repeated_signatures(tmp_path: Path) -> None:
    payload = (
        b"0             0x0             ELF, 64-bit LSB executable\n"
        b"100           0x64            ELF, 64-bit LSB executable\n"
    )
    assert len(parse_binwalk(payload, b"", tmp_path, "binwalk")) == 1
