"""Unit tests for :mod:`src.sandbox.parsers.ntlmrelayx_parser` (ARG-032).

CRITICAL security gates (C12 contract):
    * Successful relay events emit AUTH findings (CVSS 9.0, ACT).
    * NTLM ``LM:NT`` hash pairs from SAM dumps are masked before sidecar.
    * Inline credentials in target URLs are scrubbed.
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
from src.sandbox.parsers.ntlmrelayx_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_ntlmrelayx,
)

_SAM_LINE = (
    "Administrator:500:aad3b435b51404eeaad3b435b51404ee:"
    "31d6cfe0d16ae931b73c59d7e0c089c0:::"
)


def _ntlmrelayx_log() -> bytes:
    return (
        b"[*] Authenticating against smb://10.0.0.50 as CORP/Bob SUCCEED\n"
        + f"{_SAM_LINE}\n".encode()
        + b"[*] HTTP server returned 401 to 10.0.0.10\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_ntlmrelayx(b"", b"", tmp_path, "ntlmrelayx") == []


def test_relay_success_and_sam_dump_emit_findings(tmp_path: Path) -> None:
    findings = parse_ntlmrelayx(_ntlmrelayx_log(), b"", tmp_path, "ntlmrelayx")
    assert len(findings) == 2
    for finding in findings:
        assert finding.category is FindingCategory.AUTH
        assert finding.confidence is ConfidenceLevel.CONFIRMED
        assert finding.ssvc_decision is SSVCDecision.ACT
        assert finding.cvss_v3_score == 9.0


def test_ntlm_hash_pair_redacted_in_sidecar(tmp_path: Path) -> None:
    parse_ntlmrelayx(_ntlmrelayx_log(), b"", tmp_path, "ntlmrelayx")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "aad3b435b51404eeaad3b435b51404ee" not in sidecar
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in sidecar
    assert REDACTED_NT_HASH_MARKER in sidecar


def test_dedup_collapses_repeated_relay(tmp_path: Path) -> None:
    log = (
        b"[*] Authenticating against smb://10.0.0.50 as CORP/Bob SUCCEED\n"
        b"[*] Authenticating against smb://10.0.0.50 as CORP/Bob SUCCEED\n"
    )
    assert len(parse_ntlmrelayx(log, b"", tmp_path, "ntlmrelayx")) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "relay.log").write_bytes(
        b"[*] Authenticating against smb://canonical.example as CORP/admin SUCCEED\n"
    )
    decoy = b"[*] Authenticating against smb://decoy.example as CORP/admin SUCCEED\n"
    parse_ntlmrelayx(decoy, b"", tmp_path, "ntlmrelayx")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example" in sidecar


def test_kind_recorded_in_sidecar(tmp_path: Path) -> None:
    parse_ntlmrelayx(_ntlmrelayx_log(), b"", tmp_path, "ntlmrelayx")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    records = [json.loads(line) for line in sidecar.splitlines() if line]
    kinds = {r["kind"] for r in records}
    assert kinds == {"relay_success", "sam_hash_pair"}


def test_failed_attempts_skipped(tmp_path: Path) -> None:
    log = b"[*] Authenticating against smb://10.0.0.50 as CORP/Bob FAILED\n"
    assert parse_ntlmrelayx(log, b"", tmp_path, "ntlmrelayx") == []
