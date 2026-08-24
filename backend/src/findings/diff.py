"""Cross-scan finding diff (Stage F)."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from src.capabilities.schemas import CoverageStatus
from src.findings.fingerprint import (
    compute_evidence_signal_hash,
    compute_occurrence_key,
)
from src.findings.lifecycle import FindingOccurrence, FindingState, LogicalFinding


class DiffStatus(StrEnum):
    NEW = "new"
    UNCHANGED = "unchanged"
    CHANGED = "changed"
    RESOLVED_CANDIDATE = "resolved_candidate"
    RESOLVED = "resolved"
    REGRESSED = "regressed"
    NOT_TESTED = "not_tested"


class FindingDiff(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_key: StrictStr = Field(min_length=64, max_length=64)
    status: DiffStatus
    baseline_state: FindingState | None = None
    current_state: FindingState | None = None
    baseline_occurrence_key: StrictStr | None = None
    current_occurrence_key: StrictStr | None = None
    coverage_status: CoverageStatus | None = None


class FindingDiffEntry(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    finding_key: StrictStr
    status: DiffStatus
    baseline_state: StrictStr | None = None
    current_state: StrictStr | None = None


def _occurrence_map(
    occurrences: Iterable[FindingOccurrence],
) -> dict[str, FindingOccurrence]:
    return {o.finding_key: o for o in occurrences}


def diff_occurrence(
    baseline: FindingOccurrence | None,
    current: FindingOccurrence | None,
    *,
    baseline_state: FindingState | None = None,
    current_state: FindingState | None = None,
    coverage_status: CoverageStatus | None = None,
) -> DiffStatus:
    if coverage_status is CoverageStatus.NOT_TESTED:
        return DiffStatus.NOT_TESTED
    if baseline is None and current is not None:
        return DiffStatus.NEW
    if baseline is not None and current is None:
        if coverage_status in {
            CoverageStatus.COVERED_NO_FINDING,
            CoverageStatus.COVERED_WITH_FINDING,
            CoverageStatus.PARTIAL,
        }:
            if current_state is FindingState.RESOLVED:
                return DiffStatus.RESOLVED
            return DiffStatus.RESOLVED_CANDIDATE
        return DiffStatus.NOT_TESTED
    if baseline is None and current is None:
        return DiffStatus.NOT_TESTED
    assert baseline is not None and current is not None
    if current_state is FindingState.REGRESSED:
        return DiffStatus.REGRESSED
    if baseline.occurrence_key == current.occurrence_key:
        return DiffStatus.UNCHANGED
    return DiffStatus.CHANGED


def diff_findings(
    *,
    baseline_occurrences: Iterable[FindingOccurrence],
    current_occurrences: Iterable[FindingOccurrence],
    baseline_states: dict[str, FindingState] | None = None,
    current_states: dict[str, FindingState] | None = None,
    coverage_by_finding: dict[str, CoverageStatus] | None = None,
) -> tuple[FindingDiff, ...]:
    baseline_map = _occurrence_map(baseline_occurrences)
    current_map = _occurrence_map(current_occurrences)
    baseline_states = baseline_states or {}
    current_states = current_states or {}
    coverage_by_finding = coverage_by_finding or {}
    keys = set(baseline_map) | set(current_map)
    diffs: list[FindingDiff] = []
    for finding_key in sorted(keys):
        baseline = baseline_map.get(finding_key)
        current = current_map.get(finding_key)
        coverage = coverage_by_finding.get(finding_key)
        status = diff_occurrence(
            baseline,
            current,
            baseline_state=baseline_states.get(finding_key),
            current_state=current_states.get(finding_key),
            coverage_status=coverage,
        )
        diffs.append(
            FindingDiff(
                finding_key=finding_key,
                status=status,
                baseline_state=baseline_states.get(finding_key),
                current_state=current_states.get(finding_key),
                baseline_occurrence_key=baseline.occurrence_key if baseline else None,
                current_occurrence_key=current.occurrence_key if current else None,
                coverage_status=coverage,
            )
        )
    return tuple(diffs)


def occurrence_from_scan(
    *,
    finding_key: str,
    tenant_id: str,
    scan_id: str,
    scanner: str,
    detector_id: str,
    detector_version: str,
    request_signature: str,
    evidence: dict[str, object] | str,
    seen_at: datetime,
) -> FindingOccurrence:
    evidence_hash = compute_evidence_signal_hash(evidence)  # type: ignore[arg-type]
    occurrence_key = compute_occurrence_key(
        finding_key=finding_key,
        scanner=scanner,
        detector_id=detector_id,
        detector_version=detector_version,
        request_signature=request_signature,
        evidence_signal_hash=evidence_hash,
    )
    return FindingOccurrence(
        occurrence_key=occurrence_key,
        finding_key=finding_key,
        tenant_id=tenant_id,
        scan_id=scan_id,
        scanner=scanner,
        detector_id=detector_id,
        detector_version=detector_version,
        evidence_refs=(evidence_hash,),
        first_seen_at=seen_at,
        last_seen_at=seen_at,
    )


class FindingDiffService:
    def diff(
        self,
        *,
        baseline: dict[str, LogicalFinding],
        current: dict[str, LogicalFinding],
        tested_finding_keys: set[str] | None = None,
    ) -> list[FindingDiffEntry]:
        tested = tested_finding_keys or set(current.keys())
        keys = set(baseline) | set(current) | tested
        out: list[FindingDiffEntry] = []
        for key in sorted(keys):
            b = baseline.get(key)
            c = current.get(key)
            if b is None and c is not None:
                out.append(
                    FindingDiffEntry(
                        finding_key=key,
                        status=DiffStatus.NEW,
                        current_state=c.state.value,
                    )
                )
                continue
            if c is None:
                if key not in tested:
                    out.append(
                        FindingDiffEntry(
                            finding_key=key,
                            status=DiffStatus.NOT_TESTED,
                            baseline_state=b.state.value if b else None,
                        )
                    )
                elif b and b.state is FindingState.RESOLVED:
                    out.append(
                        FindingDiffEntry(
                            finding_key=key,
                            status=DiffStatus.RESOLVED,
                            baseline_state=b.state.value,
                        )
                    )
                elif b and b.state is FindingState.RESOLVED_CANDIDATE:
                    out.append(
                        FindingDiffEntry(
                            finding_key=key,
                            status=DiffStatus.RESOLVED_CANDIDATE,
                            baseline_state=b.state.value,
                        )
                    )
                else:
                    out.append(
                        FindingDiffEntry(
                            finding_key=key,
                            status=DiffStatus.NOT_TESTED,
                            baseline_state=b.state.value if b else None,
                        )
                    )
                continue
            assert b is not None
            if c.state is FindingState.REGRESSED:
                status = DiffStatus.REGRESSED
            elif c.state is FindingState.RESOLVED:
                status = DiffStatus.RESOLVED
            elif c.state is FindingState.RESOLVED_CANDIDATE:
                status = DiffStatus.RESOLVED_CANDIDATE
            elif c.state != b.state or c.occurrence_keys != b.occurrence_keys:
                status = DiffStatus.CHANGED
            else:
                status = DiffStatus.UNCHANGED
            out.append(
                FindingDiffEntry(
                    finding_key=key,
                    status=status,
                    baseline_state=b.state.value,
                    current_state=c.state.value,
                )
            )
        return out
