"""Wave 4 / Stage 1 — snapshot-reference extraction + client-safe ledger projection.

The DB-backed collect/persist paths are exercised by integration tests; these cover
the pure glue: which references the canonical snapshot exposes, and that the report
projection never leaks an internal storage key (C-29).
"""

from __future__ import annotations

from src.reports.artifact_ledger import ArtifactRecord, build_artifact_ledger
from src.reports.artifact_ledger_builder import (
    ledger_entries_for_report,
    referenced_sets_from_snapshot,
)
from src.reports.report_document import (
    ReportDocumentV1,
    ReportEvidenceRef,
    ReportFinding,
    ReportToolRun,
)


def _doc() -> ReportDocumentV1:
    return ReportDocumentV1(
        scan_id="s1",
        tenant_id="t1",
        target="http://x",
        findings=[
            ReportFinding(
                finding_id="F-1",
                title="SQLi",
                severity="high",
                evidence_ids=["E-1", "E-2"],
                raw_artifact_ref="t/s/evidence/raw-f1.bin",
            )
        ],
        evidence_references=[
            ReportEvidenceRef(
                evidence_id="E-1",
                object_key="t/s/evidence/har-1.bin",
                producer_tool_run_id="TR-9",
            ),
        ],
        tool_runs=[
            ReportToolRun(
                tool_run_id="TR-1",
                tool_name="nmap",
                raw_artifact_ref="t/s/tool/nmap-1.bin",
            ),
        ],
    )


def test_referenced_sets_cover_every_reference_channel() -> None:
    keys, ev_ids, tr_ids = referenced_sets_from_snapshot(_doc())
    assert ev_ids == {"E-1", "E-2"}
    assert "t/s/evidence/har-1.bin" in keys
    assert "t/s/evidence/raw-f1.bin" in keys
    assert "t/s/tool/nmap-1.bin" in keys
    assert tr_ids == {"TR-1", "TR-9"}


def test_report_projection_is_client_safe() -> None:
    # The report projection must carry the opaque evidence id, never the object_key.
    art = ArtifactRecord(
        scan_id="s1",
        evidence_id="E-77",
        object_key="t1/s1/evidence/har-secret.bin",
        kind="har",
        size_bytes=500,
        source="evidence",
        tool_run_id="TR-5",
    )
    entries = build_artifact_ledger(
        [art], referenced_keys=set(), referenced_evidence_ids={"E-77"}
    )
    rows = ledger_entries_for_report(entries)
    assert rows[0]["ref"] == "E-77"
    assert rows[0]["state"] == "presented"
    blob = str(rows)
    assert "t1/s1/evidence/har-secret.bin" not in blob
    assert "object_key" not in blob


def test_tool_run_projection_uses_toolrun_token() -> None:
    art = ArtifactRecord(
        scan_id="s1",
        evidence_id=None,
        object_key="t1/s1/tool/out.bin",
        kind="tool_output",
        size_bytes=10,
        source="tool_run",
        tool_run_id="TR-3",
    )
    entries = build_artifact_ledger(
        [art],
        referenced_keys=set(),
        referenced_evidence_ids=set(),
        referenced_tool_run_ids=frozenset({"TR-3"}),
    )
    rows = ledger_entries_for_report(entries)
    assert rows[0]["ref"] == "toolrun:TR-3"
    assert "t1/s1/tool/out.bin" not in str(rows)
