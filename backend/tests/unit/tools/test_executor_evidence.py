"""Wave 2 / stage 3 — tool-run evidence capture in the executor."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from src.pipeline.contracts.finding_dto import EvidenceDTO, EvidenceKind
from src.tools import executor

_NOW = datetime(2026, 1, 1, tzinfo=UTC)


class _FakePipeline:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def persist_sync(
        self,
        *,
        tool_run_id: object,
        tenant_id: object,
        scan_id: object,
        kind: EvidenceKind,
        raw_data: bytes,
        content_type: str = "application/octet-stream",
        finding_id: object = None,
    ) -> EvidenceDTO:
        self.calls.append({"kind": kind, "size": len(raw_data)})
        return EvidenceDTO(
            id=uuid4(),
            finding_id=None,
            tool_run_id=tool_run_id,  # type: ignore[arg-type]
            kind=kind,
            s3_key=f"t/s/evidence/{kind.value}-abc.bin",
            sha256="a" * 64,
        )


def test_capture_buffers_evidence_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("src.evidence.factory.get_evidence_pipeline", _FakePipeline)
    tenant, scan, trid = str(uuid4()), str(uuid4()), uuid4()
    saved, key = executor._capture_tool_run_evidence(
        tenant, scan, trid, "nmap", {"stdout": "out", "stderr": "warn"}, _NOW, _NOW
    )
    assert saved is True
    assert key == "t/s/evidence/raw_output-abc.bin"
    rows = executor.drain_pending_evidence(scan)
    assert len(rows) == 2
    assert all(r["checksum_value"] == "a" * 64 for r in rows)
    assert all(r["tool_run_id"] == str(trid) for r in rows)
    assert all(r["finding_id"] is None for r in rows)
    assert {r["description"] for r in rows} == {"stdout of nmap", "stderr of nmap"}
    # Buffer drained.
    assert executor.drain_pending_evidence(scan) == []


def test_capture_pipeline_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom() -> object:
        raise RuntimeError("no pipeline")

    monkeypatch.setattr("src.evidence.factory.get_evidence_pipeline", _boom)
    scan = str(uuid4())
    saved, key = executor._capture_tool_run_evidence(
        str(uuid4()), scan, uuid4(), "nmap", {"stdout": "x"}, _NOW, _NOW
    )
    assert saved is False
    assert key is None
    assert executor.drain_pending_evidence(scan) == []


def test_capture_persist_failure_marks_not_saved(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Boom:
        def persist_sync(self, **_kw: object) -> EvidenceDTO:
            raise RuntimeError("upload failed")

    monkeypatch.setattr("src.evidence.factory.get_evidence_pipeline", _Boom)
    scan = str(uuid4())
    saved, key = executor._capture_tool_run_evidence(
        str(uuid4()), scan, uuid4(), "nmap", {"stdout": "x"}, _NOW, _NOW
    )
    assert saved is False
    assert key is None
    assert executor.drain_pending_evidence(scan) == []


def test_capture_invalid_ids_returns_unsaved() -> None:
    saved, key = executor._capture_tool_run_evidence(
        "not-a-uuid", "also-not", uuid4(), "nmap", {"stdout": "x"}, _NOW, _NOW
    )
    assert saved is False
    assert key is None


def test_schedule_tool_run_marks_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    scan = str(uuid4())
    big = "A" * (executor._TOOL_RUN_OUTPUT_MAX_CHARS + 500)
    executor._schedule_tool_run_record(
        str(uuid4()),
        scan,
        "nmap",
        {"success": True, "stdout": big, "stderr": ""},
        _NOW,
        _NOW,
        "nmap -sV x",
        tool_run_id=uuid4(),
        evidence_saved=True,
        output_object_key="t/s/evidence/raw_output-abc.bin",
    )
    [rec] = executor.drain_pending_tool_runs(scan)
    assert rec["output_object_key"] == "t/s/evidence/raw_output-abc.bin"
    assert rec["input_params"]["evidence_saved"] is True
    assert "truncated" in rec["output_raw"]
    assert "full output in object storage" in rec["output_raw"]
    assert len(rec["output_raw"]) < len(big)
