"""Unit tests for :mod:`src.sandbox.parsers.jadx_parser` (ARG-032).

Pinned contracts:

* WARN/ERROR log lines emit INFO findings.
* ``loading X.apk/dex/jar`` rows surface as ``artifact_loaded`` INFO.
* Memory addresses are scrubbed via ``scrub_evidence_strings``.
* Cap of 500 findings respected; deduplication on
  ``(kind, fingerprint)``.
"""

from __future__ import annotations

from pathlib import Path

from src.pipeline.contracts.finding_dto import FindingCategory
from src.sandbox.parsers.jadx_parser import (
    EVIDENCE_SIDECAR_NAME,
    parse_jadx,
)


def _jadx_log() -> bytes:
    return (
        b"INFO  - loading /tmp/sample.apk\n"
        b"INFO  - processing classes.dex\n"
        b"WARN  - failed to decompile method 'foo' in class 'Bar'\n"
        b"ERROR - failed to decompile class 'com.example.Quux' (jvm 0xdeadbeef10)\n"
    )


def test_empty_stdout_returns_no_findings(tmp_path: Path) -> None:
    assert parse_jadx(b"", b"", tmp_path, "jadx") == []


def test_artifact_loaded_emits_info(tmp_path: Path) -> None:
    findings = parse_jadx(_jadx_log(), b"", tmp_path, "jadx")
    assert any(f.category is FindingCategory.INFO for f in findings)


def test_warn_and_error_emit_info_findings(tmp_path: Path) -> None:
    findings = parse_jadx(_jadx_log(), b"", tmp_path, "jadx")
    # 1 artifact_loaded + 1 WARN + 1 ERROR = 3
    assert len(findings) == 3


def test_memory_addresses_scrubbed_in_sidecar(tmp_path: Path) -> None:
    parse_jadx(_jadx_log(), b"", tmp_path, "jadx")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "0xdeadbeef10" not in sidecar


def test_dedup_collapses_repeated_warnings(tmp_path: Path) -> None:
    payload = b"WARN - identical message\nWARN - identical message\n"
    assert len(parse_jadx(payload, b"", tmp_path, "jadx")) == 1


def test_canonical_artifact_takes_precedence(tmp_path: Path) -> None:
    (tmp_path / "jadx.log").write_bytes(b"INFO - loading canonical.apk\n")
    decoy = b"INFO - loading decoy.apk\n"
    parse_jadx(decoy, b"", tmp_path, "jadx")
    sidecar = (tmp_path / EVIDENCE_SIDECAR_NAME).read_text(encoding="utf-8")
    assert "canonical.apk" in sidecar


def test_info_only_lines_skipped(tmp_path: Path) -> None:
    payload = b"INFO - processing\nDEBUG - skipped\n"
    assert parse_jadx(payload, b"", tmp_path, "jadx") == []
