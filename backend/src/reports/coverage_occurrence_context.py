"""CONT-009 — Coverage statuses and finding occurrences for report context.

Builds an honest, JSON-serialisable block that distinguishes
``not_tested`` from ``covered_no_finding`` (Stage E) and references
finding occurrences by stable sha256 keys (Stage F).

The report path is read-only: no finding/evidence deletion APIs are exposed.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from typing import Any, Final

from pydantic import ValidationError

from src.capabilities.coverage import absence_of_finding_is_not_coverage
from src.capabilities.schemas import COVERED_STATUSES, CoverageResult, CoverageStatus
from src.findings.fingerprint import finding_key_from_dict
from src.findings.lifecycle import (
    FindingOccurrence,
    FindingState,
    LogicalFinding,
)
from src.orchestration.coverage_phase_sink import get_coverage_store

SCHEMA_VERSION: Final[str] = "cont-009/v1"

_PHASE_COVERAGE_KEYS: Final[tuple[str, ...]] = (
    "coverage_accounting",
    "capability_coverage",
    "coverage_results",
    "quick_coverage",
)
_PHASE_FINDING_KEYS: Final[tuple[str, ...]] = (
    "logical_findings",
    "finding_lifecycle",
)
_PHASE_OCCURRENCE_KEYS: Final[tuple[str, ...]] = (
    "finding_occurrences",
    "occurrences",
)

_ALL_COVERAGE_STATUS_VALUES: Final[frozenset[str]] = frozenset(
    status.value for status in CoverageStatus
)


def _utcnow() -> datetime:
    return datetime.now(tz=UTC)


def _coerce_coverage_status(raw: Any) -> CoverageStatus | None:
    if isinstance(raw, CoverageStatus):
        return raw
    if not isinstance(raw, str):
        return None
    value = raw.strip().lower()
    if value not in _ALL_COVERAGE_STATUS_VALUES:
        return None
    return CoverageStatus(value)


def _coerce_finding_state(raw: Any) -> FindingState:
    if isinstance(raw, FindingState):
        return raw
    if isinstance(raw, str) and raw.strip():
        try:
            return FindingState(raw.strip().lower())
        except ValueError:
            pass
    return FindingState.CANDIDATE


def _walk_phase_outputs(
    phase_outputs: Sequence[tuple[str, dict[str, Any] | None]],
) -> list[dict[str, Any]]:
    blobs: list[dict[str, Any]] = []
    for _phase, output in phase_outputs:
        if isinstance(output, dict) and output:
            blobs.append(output)
    return blobs


def _first_nested_dict(
    blobs: Iterable[dict[str, Any]],
    keys: tuple[str, ...],
) -> dict[str, Any] | None:
    for blob in blobs:
        for key in keys:
            nested = blob.get(key)
            if isinstance(nested, dict) and nested:
                return nested
    return None


def _collect_list_items(
    blobs: Iterable[dict[str, Any]],
    *,
    top_level_keys: tuple[str, ...],
    nested_keys: tuple[str, ...] = ("results", "items", "records"),
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for blob in blobs:
        for key in top_level_keys:
            raw = blob.get(key)
            if isinstance(raw, list):
                items.extend(x for x in raw if isinstance(x, dict))
            elif isinstance(raw, dict):
                for nested_key in nested_keys:
                    nested = raw.get(nested_key)
                    if isinstance(nested, list):
                        items.extend(x for x in nested if isinstance(x, dict))
                        break
    return items


def _honest_coverage_status_from_raw(
    item: dict[str, Any],
    status: CoverageStatus,
) -> CoverageStatus:
    """Downgrade dishonest ``covered_no_finding`` without execution evidence."""
    execution_evidence_id = item.get("execution_evidence_id")
    evidence = str(execution_evidence_id).strip() if execution_evidence_id else ""
    finding_id = item.get("finding_id")
    finding_present = bool(str(finding_id).strip() if finding_id else "")
    tool_executed = bool(item.get("tool_executed")) or bool(evidence)

    if status is CoverageStatus.COVERED_NO_FINDING and not tool_executed:
        return absence_of_finding_is_not_coverage(
            prior_status=CoverageStatus.NOT_TESTED,
            finding_present=finding_present,
            execution_evidence_id=None,
        )

    if status in COVERED_STATUSES and not tool_executed:
        return CoverageStatus.NOT_TESTED

    return status


def _parse_coverage_results(
    blobs: Sequence[dict[str, Any]],
    *,
    tenant_id: str,
    scan_id: str,
) -> list[CoverageResult]:
    parsed: list[CoverageResult] = []
    for item in _collect_list_items(blobs, top_level_keys=_PHASE_COVERAGE_KEYS):
        status = _coerce_coverage_status(item.get("status"))
        if status is None:
            continue
        status = _honest_coverage_status_from_raw(item, status)
        req_id = str(item.get("requirement_id") or item.get("id") or "").strip()
        cap_id = str(item.get("capability_id") or "").strip()
        if not req_id or not cap_id:
            continue
        try:
            parsed.append(
                CoverageResult(
                    requirement_id=req_id,
                    tenant_id=str(item.get("tenant_id") or tenant_id),
                    scan_id=str(item.get("scan_id") or scan_id),
                    asset_id=str(item.get("asset_id") or "unknown"),
                    capability_id=cap_id,
                    status=status,
                    execution_evidence_id=(
                        str(item["execution_evidence_id"])
                        if item.get("execution_evidence_id")
                        else None
                    ),
                    blocked_reason=(
                        str(item["blocked_reason"]) if item.get("blocked_reason") else None
                    ),
                    finding_id=str(item["finding_id"]) if item.get("finding_id") else None,
                    reason_code=(
                        str(item["reason_code"]) if item.get("reason_code") else None
                    ),
                    template_ids=tuple(
                        str(x) for x in (item.get("template_ids") or ()) if x
                    ),
                    evidence_ids=tuple(
                        str(x) for x in (item.get("evidence_ids") or ()) if x
                    ),
                )
            )
        except (ValidationError, ValueError):
            continue
    return parsed


def _merge_sink_coverage_results(
    parsed: list[CoverageResult],
    scan_id: str,
) -> list[CoverageResult]:
    stored = get_coverage_store().get(scan_id)
    if not stored:
        return parsed
    seen = {(item.requirement_id, item.capability_id) for item in parsed}
    merged = list(parsed)
    for result in stored:
        key = (result.requirement_id, result.capability_id)
        if key in seen:
            continue
        merged.append(result)
        seen.add(key)
    return merged


def _parse_logical_findings(
    blobs: Sequence[dict[str, Any]],
) -> dict[str, LogicalFinding]:
    out: dict[str, LogicalFinding] = {}
    for blob in blobs:
        for key in _PHASE_FINDING_KEYS:
            raw = blob.get(key)
            if raw is None:
                continue
            if isinstance(raw, dict):
                iterable: Iterable[tuple[str, Any]] = raw.items()
            elif isinstance(raw, list):
                iterable = (
                    (str(item.get("finding_key") or ""), item)
                    for item in raw
                    if isinstance(item, dict)
                )
            else:
                continue
            for finding_key, payload in iterable:
                if not finding_key or not isinstance(payload, dict):
                    continue
                try:
                    out[finding_key] = LogicalFinding(
                        finding_key=finding_key,
                        tenant_id=str(payload.get("tenant_id") or ""),
                        engagement_id=str(payload.get("engagement_id") or ""),
                        state=_coerce_finding_state(payload.get("state")),
                        title=str(payload.get("title") or ""),
                        category=str(payload.get("category") or ""),
                        evidence_refs=[
                            str(x) for x in (payload.get("evidence_refs") or []) if x
                        ],
                        occurrence_keys=[
                            str(x) for x in (payload.get("occurrence_keys") or []) if x
                        ],
                        coverage_equivalent=bool(payload.get("coverage_equivalent", False)),
                    )
                except ValidationError:
                    continue
    return out


def _parse_occurrences(
    blobs: Sequence[dict[str, Any]],
) -> dict[str, FindingOccurrence]:
    out: dict[str, FindingOccurrence] = {}
    for item in _collect_list_items(blobs, top_level_keys=_PHASE_OCCURRENCE_KEYS):
        try:
            occ = FindingOccurrence.model_validate(item)
        except ValidationError:
            continue
        out[occ.occurrence_key] = occ
    return out


def _resolve_engagement_id(
    *,
    engagement_id: str | None,
    scan_options: dict[str, Any] | None,
    blobs: Sequence[dict[str, Any]],
) -> str:
    if engagement_id and engagement_id.strip():
        return engagement_id.strip()
    if isinstance(scan_options, dict):
        opt = scan_options.get("engagement_id")
        if isinstance(opt, str) and opt.strip():
            return opt.strip()
    nested = _first_nested_dict(blobs, ("coverage_accounting", "scan_metadata"))
    if nested:
        raw = nested.get("engagement_id")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
    return ""


def derive_occurrences_from_findings(
    findings: Sequence[Mapping[str, Any]],
    *,
    tenant_id: str,
    scan_id: str,
    engagement_id: str,
    seen_at: datetime | None = None,
) -> tuple[dict[str, LogicalFinding], dict[str, FindingOccurrence]]:
    """Best-effort occurrence projection from report finding dicts (read-only)."""
    from src.findings.diff import occurrence_from_scan

    logical: dict[str, LogicalFinding] = {}
    occurrences: dict[str, FindingOccurrence] = {}
    when = seen_at or _utcnow()
    tid = tenant_id.strip()
    sid = scan_id.strip()
    eid = engagement_id.strip() or sid

    for raw in findings:
        if not isinstance(raw, Mapping):
            continue
        payload = dict(raw)
        payload.setdefault("tenant_id", tid)
        payload.setdefault("engagement_id", eid)
        finding_key = str(payload.get("finding_key") or "").strip()
        if not finding_key:
            try:
                finding_key = finding_key_from_dict(payload)
            except (TypeError, ValueError):
                continue
        if len(finding_key) != 64:
            continue

        scanner = str(
            payload.get("scanner")
            or payload.get("tool")
            or payload.get("source")
            or "report_finding"
        )
        detector_id = str(payload.get("detector_id") or payload.get("title") or "finding")[:256]
        detector_version = str(payload.get("detector_version") or "1.0.0")[:64]
        request_signature = str(
            payload.get("request_signature")
            or payload.get("affected_url")
            or payload.get("location")
            or payload.get("normalized_location")
            or finding_key
        )[:2048]
        evidence = payload.get("proof_of_concept") or payload.get("evidence") or payload.get("description") or ""

        try:
            occ = occurrence_from_scan(
                finding_key=finding_key,
                tenant_id=tid,
                scan_id=sid,
                scanner=scanner,
                detector_id=detector_id,
                detector_version=detector_version,
                request_signature=request_signature,
                evidence=evidence if isinstance(evidence, (dict, str)) else str(evidence),
                seen_at=when,
            )
        except (ValidationError, ValueError):
            continue

        occurrences[occ.occurrence_key] = occ
        state = _coerce_finding_state(payload.get("lifecycle_state") or payload.get("state"))
        existing = logical.get(finding_key)
        if existing is None:
            logical[finding_key] = LogicalFinding(
                finding_key=finding_key,
                tenant_id=tid,
                engagement_id=eid,
                state=state,
                title=str(payload.get("title") or "")[:500],
                category=str(payload.get("category") or payload.get("vuln_type") or ""),
                evidence_refs=[str(x) for x in (payload.get("evidence_refs") or []) if x],
                occurrence_keys=[occ.occurrence_key],
            )
        else:
            keys = list(existing.occurrence_keys)
            if occ.occurrence_key not in keys:
                keys.append(occ.occurrence_key)
            existing.occurrence_keys = keys
            logical[finding_key] = existing

    return logical, occurrences


def _serialize_coverage_result(result: CoverageResult) -> dict[str, Any]:
    return {
        "requirement_id": result.requirement_id,
        "capability_id": result.capability_id,
        "asset_id": result.asset_id,
        "status": result.status.value,
        "execution_evidence_id": result.execution_evidence_id,
        "blocked_reason": result.blocked_reason,
        "finding_id": result.finding_id,
        "reason_code": result.reason_code,
        "template_ids": list(result.template_ids),
        "evidence_ids": list(result.evidence_ids),
        "is_covered": result.status in COVERED_STATUSES,
        "honest_no_finding": result.status is CoverageStatus.COVERED_NO_FINDING,
        "not_tested": result.status is CoverageStatus.NOT_TESTED,
    }


def _serialize_logical_finding(finding: LogicalFinding) -> dict[str, Any]:
    return {
        "finding_key": finding.finding_key,
        "state": finding.state.value,
        "title": finding.title,
        "category": finding.category,
        "occurrence_keys": list(finding.occurrence_keys),
        "evidence_ref_count": len(finding.evidence_refs),
        "coverage_equivalent": finding.coverage_equivalent,
    }


def _serialize_occurrence(occurrence: FindingOccurrence) -> dict[str, Any]:
    return {
        "occurrence_key": occurrence.occurrence_key,
        "finding_key": occurrence.finding_key,
        "scanner": occurrence.scanner,
        "detector_id": occurrence.detector_id,
        "detector_version": occurrence.detector_version,
        "evidence_ref_count": len(occurrence.evidence_refs),
        "first_seen_at": occurrence.first_seen_at.isoformat(),
        "last_seen_at": occurrence.last_seen_at.isoformat(),
    }


def _status_counts(results: Sequence[CoverageResult]) -> dict[str, int]:
    counts = {status.value: 0 for status in CoverageStatus}
    for result in results:
        counts[result.status.value] = counts.get(result.status.value, 0) + 1
    return counts


def build_coverage_occurrence_context(
    *,
    tenant_id: str,
    scan_id: str,
    phase_outputs: Sequence[tuple[str, dict[str, Any] | None]] | None = None,
    findings: Sequence[Mapping[str, Any]] | None = None,
    engagement_id: str | None = None,
    scan_options: dict[str, Any] | None = None,
    persisted_logical_findings: Mapping[str, LogicalFinding] | None = None,
    persisted_occurrences: Mapping[str, FindingOccurrence] | None = None,
) -> dict[str, Any]:
    """Assemble coverage + occurrence block for Valhalla/report JSON export."""
    blobs = _walk_phase_outputs(phase_outputs or ())
    eid = _resolve_engagement_id(
        engagement_id=engagement_id,
        scan_options=scan_options,
        blobs=blobs,
    )

    coverage_results = _parse_coverage_results(
        blobs,
        tenant_id=tenant_id,
        scan_id=scan_id,
    )
    coverage_results = _merge_sink_coverage_results(coverage_results, scan_id)
    logical_findings = _parse_logical_findings(blobs)
    occurrences = _parse_occurrences(blobs)

    if persisted_logical_findings:
        for key, finding in persisted_logical_findings.items():
            logical_findings.setdefault(key, finding)
    if persisted_occurrences:
        for key, occ in persisted_occurrences.items():
            occurrences.setdefault(key, occ)

    if findings:
        derived_logical, derived_occ = derive_occurrences_from_findings(
            findings,
            tenant_id=tenant_id,
            scan_id=scan_id,
            engagement_id=eid or scan_id,
        )
        for key, finding in derived_logical.items():
            logical_findings.setdefault(key, finding)
        for key, occ in derived_occ.items():
            occurrences.setdefault(key, occ)

    for finding in logical_findings.values():
        for occ_key in finding.occurrence_keys:
            if occ_key in occurrences and occurrences[occ_key].finding_key != finding.finding_key:
                continue

    by_capability: dict[str, dict[str, Any]] = {}
    for result in coverage_results:
        cap_id = result.capability_id or result.requirement_id
        if not cap_id:
            continue
        by_capability[cap_id] = _serialize_coverage_result(result)

    occurrence_index: dict[str, list[str]] = {}
    for occ in occurrences.values():
        occurrence_index.setdefault(occ.finding_key, [])
        if occ.occurrence_key not in occurrence_index[occ.finding_key]:
            occurrence_index[occ.finding_key].append(occ.occurrence_key)
    for finding in logical_findings.values():
        occurrence_index.setdefault(finding.finding_key, [])
        for occ_key in finding.occurrence_keys:
            if occ_key not in occurrence_index[finding.finding_key]:
                occurrence_index[finding.finding_key].append(occ_key)

    status_counts = _status_counts(coverage_results)
    not_tested_n = status_counts.get(CoverageStatus.NOT_TESTED.value, 0)
    covered_no_finding_n = status_counts.get(CoverageStatus.COVERED_NO_FINDING.value, 0)

    return {
        "schema_version": SCHEMA_VERSION,
        "tenant_id": tenant_id,
        "scan_id": scan_id,
        "engagement_id": eid or None,
        "coverage_status_enum": sorted(_ALL_COVERAGE_STATUS_VALUES),
        "coverage_status_counts": status_counts,
        "coverage_by_capability": by_capability,
        "logical_findings": {
            key: _serialize_logical_finding(finding)
            for key, finding in sorted(logical_findings.items())
        },
        "occurrences_by_key": {
            key: _serialize_occurrence(occ)
            for key, occ in sorted(occurrences.items())
        },
        "occurrence_index": {
            finding_key: sorted(keys) for finding_key, keys in sorted(occurrence_index.items())
        },
        "invariants": {
            "not_tested_distinct_from_covered_no_finding": (
                CoverageStatus.NOT_TESTED.value != CoverageStatus.COVERED_NO_FINDING.value
            ),
            "finding_deletion_forbidden": True,
            "absence_of_finding_is_not_coverage": True,
        },
        "quick_reason_codes": sorted(
            {str(result.reason_code) for result in coverage_results if result.reason_code}
        ),
        "totals": {
            "coverage_results": len(coverage_results),
            "logical_findings": len(logical_findings),
            "occurrences": len(occurrences),
            "not_tested": not_tested_n,
            "covered_no_finding": covered_no_finding_n,
        },
    }


__all__ = [
    "SCHEMA_VERSION",
    "build_coverage_occurrence_context",
    "derive_occurrences_from_findings",
]
