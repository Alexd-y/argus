"""Build a canonical :class:`ReportDocumentV1` from pipeline report data (R7).

Maps the existing ``ReportData`` (+ optional richer ``ScanReportData``) onto the
immutable snapshot so all four formats render from one source. The mapping is
tolerant (``getattr`` with defaults) so it works with the real dataclasses and
with lightweight test doubles. The evidence gate is applied by
``build_report_document`` — a ``validated`` finding without evidence refs is
downgraded to ``insufficient_evidence`` instead of being fabricated.
"""

from __future__ import annotations

from typing import Any

from src.reports.report_document import (
    ReportCoverageItem,
    ReportDocumentV1,
    ReportEvidenceRef,
    ReportFinding,
    ReportToolRun,
    build_report_document,
)

_CONFIDENCE_FLOAT: dict[str, float] = {
    "confirmed": 0.95,
    "exploitable": 0.98,
    "likely": 0.75,
    "possible": 0.5,
    "advisory": 0.25,
    "suspected": 0.4,
}

# api.schemas.Finding.validation_status → snapshot verification_status.
_VALIDATION_TO_VERIFICATION: dict[str, str] = {
    "validated": "confirmed",
    "partially_validated": "suspected",
    "unverified": "not_tested",
    "missing": "not_assessed",
}

_ALLOWED_SEVERITY = frozenset({"critical", "high", "medium", "low", "info"})


def _severity(value: Any) -> str:
    s = str(value or "info").strip().lower()
    return s if s in _ALLOWED_SEVERITY else "info"


def _confidence_float(value: Any) -> float:
    if isinstance(value, (int, float)):
        try:
            return max(0.0, min(1.0, float(value)))
        except (TypeError, ValueError):
            return 0.0
    return _CONFIDENCE_FLOAT.get(str(value or "").strip().lower(), 0.0)


def _verification_status(finding: Any) -> str:
    raw = str(getattr(finding, "validation_status", "") or "").strip().lower()
    mapped = _VALIDATION_TO_VERIFICATION.get(raw)
    if mapped:
        return mapped
    # Fall back to confidence when validation_status is absent.
    conf = str(getattr(finding, "confidence", "") or "").strip().lower()
    if conf in {"confirmed", "exploitable"}:
        return "confirmed"
    if conf in {"likely", "possible", "suspected"}:
        return "suspected"
    return "not_assessed"


def _map_finding(finding: Any, index: int) -> ReportFinding:
    finding_id = str(getattr(finding, "finding_id", None) or f"F-{index + 1}")
    evidence_refs = list(getattr(finding, "evidence_refs", None) or [])
    cwe = getattr(finding, "cwe", None)
    return ReportFinding(
        finding_id=finding_id,
        title=str(getattr(finding, "title", "") or "Untitled finding"),
        severity=_severity(getattr(finding, "severity", "info")),
        category=getattr(finding, "category", None),
        cwe=str(cwe) if cwe else None,
        description=str(getattr(finding, "description", "") or ""),
        verification_status=_verification_status(finding),
        confidence=_confidence_float(getattr(finding, "confidence", None)),
        evidence_ids=[str(e) for e in evidence_refs],
        tool_run_id=(str(getattr(finding, "tool_run_id", "")) or None)
        if getattr(finding, "tool_run_id", None)
        else None,
    )


def _map_tool_runs(scan_report_data: Any) -> list[ReportToolRun]:
    runs = getattr(scan_report_data, "tool_runs", None) or []
    out: list[ReportToolRun] = []
    for run in runs:
        get = run.get if isinstance(run, dict) else (lambda k, d=None, r=run: getattr(r, k, d))
        tool_run_id = str(get("id", "") or get("tool_run_id", "") or "")
        tool_name = str(get("tool_name", "") or get("tool", "") or "unknown")
        if not tool_run_id:
            tool_run_id = f"TR-{tool_name}-{len(out) + 1}"
        out.append(
            ReportToolRun(
                tool_run_id=tool_run_id,
                tool_name=tool_name,
                status=str(get("status", "unknown") or "unknown"),
                parser_status=get("parser_status", None),
            )
        )
    return out


def _map_coverage(scan_report_data: Any) -> list[ReportCoverageItem]:
    coverage = getattr(scan_report_data, "coverage_occurrence", None) or []
    out: list[ReportCoverageItem] = []
    for item in coverage:
        if not isinstance(item, dict):
            continue
        cap = item.get("capability_id") or item.get("requirement_id")
        if not cap:
            continue
        out.append(
            ReportCoverageItem(
                capability_id=str(cap),
                status=str(item.get("status", "not_assessed") or "not_assessed"),
                reason_code=item.get("reason_code"),
                evidence_ids=[str(e) for e in (item.get("evidence_ids") or [])],
            )
        )
    return out


def _map_evidence(report_data: Any) -> list[ReportEvidenceRef]:
    out: list[ReportEvidenceRef] = []
    for entry in getattr(report_data, "evidence", None) or []:
        get = entry.get if isinstance(entry, dict) else (lambda k, d=None, e=entry: getattr(e, k, d))
        object_key = get("object_key", None)
        finding_id = get("finding_id", None)
        eid = str(object_key or finding_id or f"E-{len(out) + 1}")
        out.append(
            ReportEvidenceRef(
                evidence_id=eid,
                kind=str(get("kind", "artifact") or "artifact"),
                object_key=str(object_key) if object_key else None,
                description=get("description", None),
            )
        )
    return out


def build_snapshot_from_report_data(
    report_data: Any,
    *,
    scan_meta: dict[str, Any] | None = None,
    scan_report_data: Any | None = None,
    registry_versions: dict[str, Any] | None = None,
    generated_at: Any | None = None,
) -> ReportDocumentV1:
    """Assemble a canonical snapshot from pipeline data (evidence gate applied)."""
    meta = scan_meta or {}
    scan_row = getattr(scan_report_data, "scan", None) if scan_report_data is not None else None

    def _meta(key: str, *scan_attrs: str) -> Any:
        if meta.get(key) is not None:
            return meta.get(key)
        for attr in scan_attrs:
            value = getattr(scan_row, attr, None)
            if value is not None:
                return value
        return None

    findings = [
        _map_finding(f, i) for i, f in enumerate(getattr(report_data, "findings", None) or [])
    ]

    tool_runs = _map_tool_runs(scan_report_data) if scan_report_data is not None else []
    coverage = _map_coverage(scan_report_data) if scan_report_data is not None else []
    evidence_refs = _map_evidence(report_data)

    not_assessed = [c.capability_id for c in coverage if c.status != "tested"]
    tested = [c.capability_id for c in coverage if c.status == "tested"]

    return build_report_document(
        scan_id=str(meta.get("scan_id") or getattr(report_data, "scan_id", "") or "unknown"),
        tenant_id=str(meta.get("tenant_id") or getattr(report_data, "tenant_id", "") or "unknown"),
        target=str(meta.get("target") or getattr(report_data, "target", "") or ""),
        scan_profile=_meta("scan_profile", "scan_profile"),
        resolved_scan_mode=_meta("resolved_scan_mode", "resolved_scan_mode", "scan_mode"),
        execution_mode=_meta("execution_mode", "execution_mode"),
        quick_profile=_meta("quick_profile", "quick_profile"),
        nuclei_profile=_meta("nuclei_profile", "nuclei_profile"),
        started_at=meta.get("started_at"),
        completed_at=meta.get("completed_at") or getattr(report_data, "created_at", None),
        scope_summary=meta.get("scope_summary") or {},
        profile_limits=meta.get("profile_limits") or {},
        tool_runs=tool_runs,
        tested_capabilities=tested,
        not_assessed_capabilities=not_assessed,
        coverage=coverage,
        findings=findings,
        evidence_references=evidence_refs,
        limitations=list(meta.get("limitations") or []),
        registry_versions=registry_versions or meta.get("registry_versions") or {},
        generated_at=generated_at,
    )


__all__ = ["build_snapshot_from_report_data"]
