"""Unit tests for :mod:`src.evidence.raw_evidence` (wave 2 / stage 2)."""

from __future__ import annotations

from pathlib import Path

from src.evidence.raw_evidence import (
    RawEvidence,
    classify_artifact,
    gather_workdir_evidence,
    raw_evidence_from_bytes,
)
from src.pipeline.contracts.finding_dto import EvidenceKind


def test_classify_streams_and_extensions() -> None:
    assert classify_artifact("stdout.log")[0] is EvidenceKind.RAW_OUTPUT
    assert classify_artifact("stderr")[0] is EvidenceKind.RAW_OUTPUT
    assert classify_artifact("shot.png") == (EvidenceKind.SCREENSHOT, "image/png")
    assert classify_artifact("capture.har")[0] is EvidenceKind.HAR
    assert classify_artifact("dump.pcap")[0] is EvidenceKind.PCAP
    # Unknown extension falls back to raw output / octet-stream.
    assert classify_artifact("weird.bin") == (EvidenceKind.RAW_OUTPUT, "application/octet-stream")


def test_raw_evidence_from_bytes_truncates() -> None:
    ev = raw_evidence_from_bytes(
        kind=EvidenceKind.RAW_OUTPUT,
        data=b"x" * 100,
        content_type="text/plain",
        source="stdout",
        max_bytes=10,
    )
    assert ev.truncated is True
    assert ev.original_size == 100
    assert ev.size == 10


def test_raw_evidence_from_bytes_no_truncation() -> None:
    ev = raw_evidence_from_bytes(
        kind=EvidenceKind.RAW_OUTPUT,
        data=b"short",
        content_type="text/plain",
        source="stdout",
        max_bytes=1000,
    )
    assert ev.truncated is False
    assert isinstance(ev, RawEvidence)


def test_gather_respects_run_budget(tmp_path: Path) -> None:
    # Three 100-byte files, run budget 150 -> later files get truncated, none dropped.
    for i in range(3):
        (tmp_path / f"f{i}.txt").write_bytes(b"y" * 100)
    out = gather_workdir_evidence(tmp_path, max_artifact_bytes=1000, max_run_bytes=150)
    assert len(out) == 3  # every file recorded, never silently skipped
    assert sum(e.size for e in out) <= 150
    assert any(e.truncated for e in out)
    assert all(e.original_size == 100 for e in out)


def test_gather_missing_workdir_returns_empty(tmp_path: Path) -> None:
    assert gather_workdir_evidence(tmp_path / "nope", max_artifact_bytes=10, max_run_bytes=10) == []
