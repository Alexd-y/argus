"""Unit tests for :mod:`src.sandbox.parsers.patator_parser` (ARG-032).

CRITICAL security gate (C12 contract):
    Cleartext ``pass=`` values are redacted before any FindingDTO is built.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers._text_base import REDACTED_PASSWORD_MARKER
from src.sandbox.parsers.patator_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_patator,
)


def _patator_output() -> bytes:
    return (
        b"11:42:01 patator INFO - 0 1 1 1.0 | host=10.0.0.1:22:user=root:pass=toor [Found]\n"
        b"11:42:02 patator INFO - 0 2 1 1.0 | host=10.0.0.1:user=admin:pass=hunter2 [200]\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_patator(b"", b"", tmp_path, "patator") == []


def test_one_finding_per_credential(tmp_path: Path) -> None:
    findings = parse_patator(_patator_output(), b"", tmp_path, "patator")
    assert len(findings) == 2
    assert all(f.category is FindingCategory.AUTH for f in findings)


def test_password_redacted_in_sidecar(tmp_path: Path) -> None:
    parse_patator(_patator_output(), b"", tmp_path, "patator")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "toor" not in sidecar
    assert "hunter2" not in sidecar
    assert REDACTED_PASSWORD_MARKER in sidecar


def test_dedup_on_host_user(tmp_path: Path) -> None:
    payload = (
        b"host=10.0.0.1:user=root:pass=a [200]\nhost=10.0.0.1:user=root:pass=b [200]\n"
    )
    assert len(parse_patator(payload, b"", tmp_path, "patator")) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "patator.log").write_bytes(
        b"host=canonical.example:user=admin:pass=pwd [Found]\n"
    )
    decoy = b"host=decoy.example:user=admin:pass=pwd [Found]\n"
    parse_patator(decoy, b"", tmp_path, "patator")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.example" in sidecar


def test_status_recorded_in_sidecar(tmp_path: Path) -> None:
    parse_patator(_patator_output(), b"", tmp_path, "patator")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    statuses = {json.loads(line)["status"] for line in sidecar.splitlines() if line}
    assert "Found" in statuses or "200" in statuses


def test_failed_attempts_skipped(tmp_path: Path) -> None:
    payload = b"host=10.0.0.1:user=root:pass=wrong [401]\n"
    assert parse_patator(payload, b"", tmp_path, "patator") == []
