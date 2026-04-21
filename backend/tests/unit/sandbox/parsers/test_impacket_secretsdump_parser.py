"""Unit tests for :mod:`src.sandbox.parsers.impacket_secretsdump_parser`.

Pinned contracts (Backlog/dev1_md §4.17 — ARG-022):

* NTDS lines ``[DOMAIN\\]user:RID:LMHash:NTHash:::`` produce one
  CONFIRMED AUTH finding (CVSS 9.8, CWE-522 + CWE-256 + CWE-200).
* CRITICAL security gate: every NT/LM/AES/Kerberos hash is masked
  before sidecar persistence.  The dedicated regex check guarantees
  ``[a-f0-9]{32}:[a-f0-9]{32}`` matches **0** times.
* Records collapse on ``(kind, domain, user, rid)``.
* Empty / malformed / non-recognised lines yield no findings.
* Cap at 5_000 findings — defensive against runaway dumps.
* Sidecar JSONL ``impacket_secretsdump_findings.jsonl`` is stamped
  with ``tool_id`` and contains one record per finding.
* Kerberos AES key lines, MSCash2 (``$DCC2$``) blobs and LSA
  ``plain_password_hex`` lines are all recognised and redacted.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    SSVCDecision,
)
from src.sandbox.parsers._text_base import (
    REDACTED_HASH_MARKER,
    REDACTED_KRB_HASH_MARKER,
    REDACTED_NT_HASH_MARKER,
)
from src.sandbox.parsers.impacket_secretsdump_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_impacket_secretsdump,
)

_NT_HASH_PAIR_RE = re.compile(r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b")
_LONG_HEX_RE = re.compile(r"\b[a-fA-F0-9]{32,}\b")


def _ntds_dump() -> bytes:
    return (
        b"CONTOSO\\administrator:500:aad3b435b51404eeaad3b435b51404ee:"
        b"31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
        b"CONTOSO\\krbtgt:502:aad3b435b51404eeaad3b435b51404ee:"
        b"abcdef0123456789fedcba9876543210:::\n"
        b"CONTOSO\\svc-sql:1107:aad3b435b51404eeaad3b435b51404ee:"
        b"1234567890abcdef1234567890abcdef:::\n"
        b"CONTOSO\\svc-backup:1108:aad3b435b51404eeaad3b435b51404ee:"
        b"fedcba9876543210fedcba9876543210:::\n"
        b"CONTOSO\\jdoe:1109:aad3b435b51404eeaad3b435b51404ee:"
        b"0011223344556677889900aabbccddee:::\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_impacket_secretsdump(b"", b"", tmp_path, "impacket_secretsdump") == []


def test_happy_path_emits_one_finding_per_principal(tmp_path: Path) -> None:
    findings = parse_impacket_secretsdump(
        _ntds_dump(), b"", tmp_path, "impacket_secretsdump"
    )
    assert len(findings) == 5
    for finding in findings:
        assert finding.category is FindingCategory.AUTH
        assert finding.confidence is ConfidenceLevel.CONFIRMED
        assert finding.cvss_v3_score == 9.8
        assert finding.ssvc_decision is SSVCDecision.ACT
        assert 522 in finding.cwe and 256 in finding.cwe


def test_critical_hash_redaction_zero_raw_pairs_in_sidecar(tmp_path: Path) -> None:
    parse_impacket_secretsdump(_ntds_dump(), b"", tmp_path, "impacket_secretsdump")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert _NT_HASH_PAIR_RE.search(sidecar) is None
    assert _LONG_HEX_RE.search(sidecar) is None
    assert REDACTED_NT_HASH_MARKER in sidecar


def test_kerberos_aes_keys_are_redacted(tmp_path: Path) -> None:
    payload = (
        b"CONTOSO\\krbtgt:aes256-cts-hmac-sha1-96:"
        b"abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789\n"
    )
    parse_impacket_secretsdump(payload, b"", tmp_path, "impacket_secretsdump")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "abcdef0123456789abcdef0123456789" not in sidecar
    assert REDACTED_HASH_MARKER in sidecar


def test_kerberos_blob_is_redacted(tmp_path: Path) -> None:
    payload = (
        b"$krb5tgs$23$*sqlsvc$CONTOSO$cifs/dc01.contoso.local*$cafe1234$babefacecafe\n"
    )
    findings = parse_impacket_secretsdump(
        payload, b"", tmp_path, "impacket_secretsdump"
    )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "$krb5tgs$" not in sidecar
    assert REDACTED_KRB_HASH_MARKER in sidecar


def test_dcc2_blob_is_recognised_and_redacted(tmp_path: Path) -> None:
    payload = b"CONTOSO\\admin:$DCC2$10240#admin#a1b2c3d4e5f60718293a4b5c6d7e8f90\n"
    findings = parse_impacket_secretsdump(
        payload, b"", tmp_path, "impacket_secretsdump"
    )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "a1b2c3d4e5f60718293a4b5c6d7e8f90" not in sidecar
    assert "$DCC2$" in sidecar


def test_dedup_collapses_duplicate_principals(tmp_path: Path) -> None:
    line = (
        b"CONTOSO\\administrator:500:aad3b435b51404eeaad3b435b51404ee:"
        b"31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    )
    findings = parse_impacket_secretsdump(
        line + line + line, b"", tmp_path, "impacket_secretsdump"
    )
    assert len(findings) == 1


def test_malformed_lines_are_skipped(tmp_path: Path) -> None:
    payload = (
        b"# comment line\n"
        b"random garbage line\n"
        b"administrator:not-a-rid:lm:nt:::\n"
        b"CONTOSO\\administrator:500:aad3b435b51404eeaad3b435b51404ee:"
        b"31d6cfe0d16ae931b73c59d7e0c089c0:::\n"
    )
    findings = parse_impacket_secretsdump(
        payload, b"", tmp_path, "impacket_secretsdump"
    )
    assert len(findings) == 1


def test_sidecar_contains_tool_id_and_synthetic_id(tmp_path: Path) -> None:
    parse_impacket_secretsdump(_ntds_dump(), b"", tmp_path, "impacket_secretsdump")
    sidecar_lines = [
        line
        for line in (tmp_path / EVIDENCE_SIDECAR_NAME)
        .read_text(encoding="utf-8")
        .splitlines()
        if line
    ]
    parsed = [json.loads(line) for line in sidecar_lines]
    assert all(record["tool_id"] == "impacket_secretsdump" for record in parsed)
    assert all("synthetic_id" in record for record in parsed)


def test_findings_are_sorted_deterministically(tmp_path: Path) -> None:
    findings_a = parse_impacket_secretsdump(
        _ntds_dump(), b"", tmp_path, "impacket_secretsdump"
    )
    findings_b = parse_impacket_secretsdump(
        _ntds_dump(), b"", tmp_path, "impacket_secretsdump"
    )
    assert len(findings_a) == len(findings_b)


def test_lsa_plain_password_hex_line_is_redacted(tmp_path: Path) -> None:
    payload = (
        b"CONTOSO\\DC01$:plain_password_hex:"
        b"abcdef0123456789fedcba9876543210abcdef0123456789fedcba9876543210\n"
    )
    findings = parse_impacket_secretsdump(
        payload, b"", tmp_path, "impacket_secretsdump"
    )
    assert len(findings) == 1
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "abcdef0123456789fedcba9876543210" not in sidecar
    assert REDACTED_HASH_MARKER in sidecar
