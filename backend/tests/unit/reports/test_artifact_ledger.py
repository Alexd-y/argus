"""Wave 4 / Stage 1 — per-artifact accounting ledger (R-6.1.1 / R-6.1.2 / R-7.2).

Every artifact a scan produced is accounted for exactly once: ``presented`` (its
reference reaches the report), ``excluded`` (a *closed-enum* reason), or
``unprocessed`` — and an ``unprocessed`` artifact is a release blocker, never a
silent drop. These prove the pure reconciliation + the fail-closed blocker.
"""

from __future__ import annotations

from src.reports.artifact_ledger import (
    ArtifactRecord,
    ExclusionReason,
    LedgerState,
    build_artifact_ledger,
    ledger_release_blockers,
    ledger_summary,
)

_SCAN = "scan-1"


def _rec(**kw) -> ArtifactRecord:
    base = dict(
        scan_id=_SCAN,
        evidence_id=None,
        object_key=None,
        kind="raw_output",
        size_bytes=100,
        source="evidence",
        tool_run_id=None,
    )
    base.update(kw)
    return ArtifactRecord(**base)


def test_referenced_by_evidence_id_is_presented() -> None:
    art = _rec(evidence_id="E-1", object_key="t/s/evidence/har-abc.bin")
    entries = build_artifact_ledger(
        [art], referenced_keys=set(), referenced_evidence_ids={"E-1"}
    )
    assert len(entries) == 1
    assert entries[0].state == LedgerState.PRESENTED
    assert entries[0].exclusion_reason is None


def test_referenced_by_object_key_is_presented() -> None:
    art = _rec(evidence_id="E-2", object_key="t/s/evidence/pcap-xyz.bin")
    entries = build_artifact_ledger(
        [art], referenced_keys={"t/s/evidence/pcap-xyz.bin"}, referenced_evidence_ids=set()
    )
    assert entries[0].state == LedgerState.PRESENTED


def test_unreferenced_artifact_is_unprocessed_and_blocks() -> None:
    art = _rec(evidence_id="E-3", object_key="t/s/evidence/raw-3.bin")
    entries = build_artifact_ledger([art], referenced_keys=set(), referenced_evidence_ids=set())
    assert entries[0].state == LedgerState.UNPROCESSED
    blockers = ledger_release_blockers(entries)
    assert len(blockers) == 1
    assert "unprocessed" in blockers[0].lower()


def test_empty_artifact_is_excluded_not_unprocessed() -> None:
    # size_bytes == 0 → EMPTY_ARTIFACT exclusion (R-7.2), never a release blocker.
    art = _rec(evidence_id="E-4", object_key="t/s/evidence/raw-4.bin", size_bytes=0)
    entries = build_artifact_ledger([art], referenced_keys=set(), referenced_evidence_ids=set())
    assert entries[0].state == LedgerState.EXCLUDED
    assert entries[0].exclusion_reason == ExclusionReason.EMPTY_ARTIFACT
    assert ledger_release_blockers(entries) == []


def test_oversize_artifact_is_excluded_size_limit() -> None:
    art = _rec(evidence_id="E-5", object_key="t/s/evidence/raw-5.bin", size_bytes=5000)
    entries = build_artifact_ledger(
        [art], referenced_keys=set(), referenced_evidence_ids=set(), size_limit_bytes=1000
    )
    assert entries[0].state == LedgerState.EXCLUDED
    assert entries[0].exclusion_reason == ExclusionReason.SIZE_LIMIT


def test_tenant_policy_excluded_kind() -> None:
    art = _rec(evidence_id="E-6", object_key="t/s/evidence/sarif-6.bin", kind="sarif")
    entries = build_artifact_ledger(
        [art],
        referenced_keys=set(),
        referenced_evidence_ids=set(),
        tenant_excluded_kinds=frozenset({"sarif"}),
    )
    assert entries[0].state == LedgerState.EXCLUDED
    assert entries[0].exclusion_reason == ExclusionReason.TENANT_POLICY


def test_service_output_kind_excluded() -> None:
    art = _rec(evidence_id="E-7", object_key="t/s/evidence/hb-7.bin", kind="heartbeat")
    entries = build_artifact_ledger(
        [art],
        referenced_keys=set(),
        referenced_evidence_ids=set(),
        service_output_kinds=frozenset({"heartbeat"}),
    )
    assert entries[0].state == LedgerState.EXCLUDED
    assert entries[0].exclusion_reason == ExclusionReason.SERVICE_OUTPUT


def test_duplicate_object_key_is_excluded_once() -> None:
    # Two artifacts share an object_key: the first (lower id) is presented/unprocessed,
    # the second is a DUPLICATE exclusion — not a second unprocessed blocker.
    a = _rec(evidence_id="E-8a", object_key="t/s/evidence/dup.bin")
    b = _rec(evidence_id="E-8b", object_key="t/s/evidence/dup.bin")
    entries = build_artifact_ledger(
        [a, b], referenced_keys={"t/s/evidence/dup.bin"}, referenced_evidence_ids=set()
    )
    states = {e.artifact.evidence_id: e for e in entries}
    assert states["E-8a"].state == LedgerState.PRESENTED
    assert states["E-8b"].state == LedgerState.EXCLUDED
    assert states["E-8b"].exclusion_reason == ExclusionReason.DUPLICATE


def test_tool_run_output_presented_via_execution_log() -> None:
    # A tool-run output artifact is presented when its run appears in the execution log
    # (referenced by tool_run_id), even without an evidence id or a direct key ref.
    art = _rec(
        evidence_id=None,
        object_key="t/s/tool/nmap-out.bin",
        kind="tool_output",
        source="tool_run",
        tool_run_id="TR-1",
    )
    entries = build_artifact_ledger(
        [art],
        referenced_keys=set(),
        referenced_evidence_ids=set(),
        referenced_tool_run_ids=frozenset({"TR-1"}),
    )
    assert entries[0].state == LedgerState.PRESENTED


def test_tool_run_output_not_in_log_is_unprocessed() -> None:
    art = _rec(
        evidence_id=None,
        object_key="t/s/tool/orphan-out.bin",
        kind="tool_output",
        source="tool_run",
        tool_run_id="TR-2",
    )
    entries = build_artifact_ledger(
        [art],
        referenced_keys=set(),
        referenced_evidence_ids=set(),
        referenced_tool_run_ids=frozenset({"TR-1"}),
    )
    assert entries[0].state == LedgerState.UNPROCESSED


def test_presentation_wins_over_exclusion() -> None:
    # A referenced-but-empty artifact is PRESENTED (reference wins); only unreferenced
    # artifacts are evaluated against the exclusion rules.
    art = _rec(evidence_id="E-9", object_key="t/s/evidence/raw-9.bin", size_bytes=0)
    entries = build_artifact_ledger(
        [art], referenced_keys=set(), referenced_evidence_ids={"E-9"}
    )
    assert entries[0].state == LedgerState.PRESENTED


def test_summary_counts_by_state_and_reason() -> None:
    arts = [
        _rec(evidence_id="P1", object_key="k1"),
        _rec(evidence_id="X1", object_key="k2", size_bytes=0),
        _rec(evidence_id="U1", object_key="k3"),
    ]
    entries = build_artifact_ledger(
        arts, referenced_keys=set(), referenced_evidence_ids={"P1"}
    )
    summ = ledger_summary(entries)
    assert summ["total"] == 3
    assert summ["presented"] == 1
    assert summ["excluded"] == 1
    assert summ["unprocessed"] == 1
    assert summ["by_reason"]["empty_artifact"] == 1


def test_exclusion_reasons_are_a_closed_enum() -> None:
    # The whole point of R-6.1.1: reasons are a fixed vocabulary, not free text.
    assert {r.value for r in ExclusionReason} == {
        "duplicate",
        "size_limit",
        "tenant_policy",
        "service_output",
        "empty_artifact",
    }
