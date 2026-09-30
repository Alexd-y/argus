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

from src.core.config import settings
from src.findings.severity import SeverityBand, normalize_severity
from src.reports.engagement_builder import build_engagement_metadata, engagement_is_empty
from src.reports.poc_validation import (
    evaluate_class_confirmation,
    resolve_confirmation_class,
)
from src.reports.report_document import (
    ReportCoverageItem,
    ReportDocumentV1,
    ReportEvidenceRef,
    ReportFinding,
    ReportPoC,
    ReportSurfaceItem,
    ReportToolRun,
    build_report_document,
)
from src.reports.snapshot_completeness_gate import is_pseudo_evidence
from src.reports.valhalla_narrative_builder import (
    build_attack_narrative,
    build_exploit_chains,
)
from src.reports.wstg_report import build_wstg_block

#: Provable verification statuses that a failed class-confirmation rule downgrades.
_PROVABLE = frozenset({"confirmed", "exploitable"})

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

#: Snapshot band → canonical band mapping. ``informational`` collapses to the
#: snapshot's ``info`` bucket; ``unknown`` stays ``unknown`` (never folded into
#: ``info`` or ``low``, per docs/finding-severity-and-counting.md).
_BAND_TO_SNAPSHOT: dict[SeverityBand, str] = {
    SeverityBand.CRITICAL: "critical",
    SeverityBand.HIGH: "high",
    SeverityBand.MEDIUM: "medium",
    SeverityBand.LOW: "low",
    SeverityBand.INFORMATIONAL: "info",
    SeverityBand.UNKNOWN: "unknown",
}


def _severity(value: Any) -> str:
    """Canonical snapshot severity — single source of truth (no silent folding).

    Routes through :func:`src.findings.severity.normalize_severity` so a blank
    or unrecognised label becomes ``unknown`` (surfaced honestly) instead of a
    fabricated ``info``.
    """
    return _BAND_TO_SNAPSHOT[normalize_severity(value)]


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


def _map_poc(finding: Any) -> ReportPoC | None:
    """Build a :class:`ReportPoC` from ``Finding.proof_of_concept`` + http_evidence.

    Maps the canonical PoC keys (see poc_schema.PROOF_OF_CONCEPT_KEYS) onto the
    snapshot's PoC card so payload / command / request / response / discriminator /
    negative control survive into every format. Returns ``None`` when there is no PoC
    material, so a finding without evidence renders no empty card.
    """
    poc = getattr(finding, "proof_of_concept", None)
    if isinstance(poc, dict):
        root = (
            poc.get("proof_of_concept", poc)
            if isinstance(poc.get("proof_of_concept"), dict)
            else poc
        )
    else:
        root = {}
    http_ev = getattr(finding, "http_evidence", None)
    if isinstance(http_ev, dict):
        req = root.get("request") or http_ev.get("request") or http_ev.get("raw_request")
        resp = root.get("response") or http_ev.get("response") or http_ev.get("raw_response")
    else:
        req = root.get("request")
        resp = root.get("response") or root.get("response_snippet")

    neg = None
    if root.get("negative_control_url") or root.get("negative_control_result"):
        neg = " ".join(
            str(x)
            for x in (root.get("negative_control_url"), root.get("negative_control_result"))
            if x
        )
    fields = {
        "tool": root.get("tool"),
        "payload": root.get("payload") or root.get("payload_used") or root.get("payload_entered"),
        "command": root.get("curl_command") or root.get("replay_command"),
        "http_request": req,
        "http_response": resp,
        "observation": root.get("command_output") or root.get("cmd_output") or root.get("context"),
        "oast_callback": root.get("oast_callback") or root.get("oast"),
        "negative_control": neg,
        "screenshot_ref": root.get("screenshot_key") or root.get("poc_screenshot_url"),
        "discriminator": root.get("discriminator") or root.get("verification_method"),
        "canary": root.get("canary"),
    }
    if not any(v for v in fields.values()):
        return None
    return ReportPoC(**{k: v for k, v in fields.items() if v})


def _map_finding(
    finding: Any, index: int, *, evidence_keys: list[str] | None = None
) -> ReportFinding:
    finding_id = str(getattr(finding, "finding_id", None) or f"F-{index + 1}")
    evidence_refs = list(getattr(finding, "evidence_refs", None) or [])
    # A2-populate: fold in resolvable artifact keys from persisted Evidence rows
    # so the finding's evidence_ids reference real, gate-verifiable artifacts
    # (finding → evidence → run/session) instead of only opaque refs.
    resolvable = [k for k in (evidence_keys or []) if k]
    for key in resolvable:
        if key not in evidence_refs:
            evidence_refs.append(key)
    cwe = getattr(finding, "cwe", None)
    # Evidence-contract provenance (A2): populate validator + raw artifact ref so
    # findings trace to a producer and a stored artifact instead of being blank.
    validator = (
        getattr(finding, "validator_id", None)
        or getattr(finding, "tool_name", None)
        or getattr(finding, "source_tool", None)
    )
    raw_ref = getattr(finding, "raw_artifact_ref", None)
    if not raw_ref:
        poc = getattr(finding, "proof_of_concept", None)
        if isinstance(poc, dict):
            raw_ref = (
                poc.get("screenshot_key")
                or poc.get("artifact_key")
                or poc.get("object_key")
                or poc.get("raw_response_key")
            )
    if not raw_ref and resolvable:
        raw_ref = resolvable[0]

    title = str(getattr(finding, "title", "") or "Untitled finding")
    owasp = getattr(finding, "owasp_category", None)
    cvss_vector = getattr(finding, "cvss_vector", None)
    cvss_raw = getattr(finding, "cvss_score", None) or getattr(finding, "cvss", None)
    # C-20: 0.0 is not a CVSS assessment — treat it as "no score" (null), not a value.
    cvss_score = (
        float(cvss_raw) if isinstance(cvss_raw, (int, float)) and float(cvss_raw) > 0.0 else None
    )
    poc = _map_poc(finding)
    verification = _verification_status(finding)

    # Phase J integration: enforce the per-class confirmation bar on real data. A
    # provable finding whose PoC does not meet its class rule is downgraded to
    # ``suspected`` and the reason is recorded for printing (prompt §15.2).
    confirmation_class = None
    downgrade_reason = None
    cls = resolve_confirmation_class(f"{title} {cwe or ''}")
    if cls is not None:
        confirmation_class = cls.value
        if settings.valhalla_senior_poc_gate_enabled and verification in _PROVABLE:
            poc_payload = getattr(finding, "proof_of_concept", None) or {}
            result = evaluate_class_confirmation(
                cls, poc_payload if isinstance(poc_payload, dict) else {}
            )
            if not result.confirmed:
                downgrade_reason = result.reason
                verification = "suspected"

    # R-17 — pseudo-evidence (tool:*/recon:*) is not proof. A provable finding whose
    # only evidence is pseudo (no resolvable artifact) is capped at ``suspected``.
    ev_ids = [str(e) for e in evidence_refs]
    only_pseudo = bool(ev_ids) and all(is_pseudo_evidence(e) for e in ev_ids) and not raw_ref
    if verification in _PROVABLE and only_pseudo:
        verification = "suspected"
        downgrade_reason = downgrade_reason or "R-17: only pseudo-evidence (tool:*/recon:*)"

    poc_obj = poc

    def _fget(*names: str) -> Any:
        for name in names:
            val = getattr(finding, name, None)
            if val not in (None, ""):
                return val
        return None

    port_val = _fget("port")
    return ReportFinding(
        finding_id=finding_id,
        title=title,
        severity=_severity(getattr(finding, "severity", "info")),
        category=getattr(finding, "category", None),
        cwe=str(cwe) if cwe else None,
        description=str(getattr(finding, "description", "") or ""),
        verification_status=verification,
        confidence=_confidence_float(getattr(finding, "confidence", None)),
        evidence_ids=ev_ids,
        tool_run_id=(
            (str(getattr(finding, "tool_run_id", "")) or None)
            if getattr(finding, "tool_run_id", None)
            else None
        ),
        validator_id=str(validator) if validator else None,
        raw_artifact_ref=str(raw_ref) if raw_ref else None,
        owasp_category=str(owasp) if owasp else None,
        cvss_vector=str(cvss_vector) if cvss_vector else None,
        cvss_score=cvss_score,
        confirmation_class=confirmation_class,
        downgrade_reason=downgrade_reason,
        poc=poc_obj,
        # Phase U (§30.1) — object identity + impact, mapped from the finding.
        asset=_str_or_none(_fget("asset", "affected_asset", "affected_url", "url")),
        ip=_str_or_none(_fget("ip", "ip_address")),
        port=int(port_val) if isinstance(port_val, int) else None,
        protocol=_str_or_none(_fget("protocol")),
        scheme=_str_or_none(_fget("scheme")),
        url=_str_or_none(_fget("url", "affected_url", "endpoint")),
        path=_str_or_none(_fget("path")),
        parameter=_str_or_none(_fget("parameter", "affected_parameter")),
        component=_str_or_none(_fget("component", "affected_component")),
        observed_version=_str_or_none(_fget("observed_version", "version")),
        observed_impact=(poc_obj.observed_impact if poc_obj else None),
        potential_impact=(poc_obj.potential_impact if poc_obj else None),
        blast_radius=(poc_obj.blast_radius if poc_obj else None),
    )


def _str_or_none(value: Any) -> str | None:
    return str(value) if value not in (None, "") else None


def _map_tool_runs(scan_report_data: Any) -> list[ReportToolRun]:
    runs = getattr(scan_report_data, "tool_runs", None) or []
    out: list[ReportToolRun] = []
    for run in runs:
        get = run.get if isinstance(run, dict) else (lambda k, d=None, r=run: getattr(r, k, d))
        tool_run_id = str(get("id", "") or get("tool_run_id", "") or "")
        tool_name = str(get("tool_name", "") or get("tool", "") or "unknown")
        if not tool_run_id:
            tool_run_id = f"TR-{tool_name}-{len(out) + 1}"
        status_raw = str(get("status", "unknown") or "unknown")
        raw_artifact_ref = _str_or_none(
            get("raw_artifact_ref", None) or get("output_object_key", None)
        )
        parser_status = get("parser_status", None)
        # R-15 — a "success" run with neither artifact nor parser output is not a
        # meaningful success; record it honestly as completed_no_output.
        if status_raw.lower() == "success" and not raw_artifact_ref and not parser_status:
            status_raw = "completed_no_output"
        exit_code = get("exit_code", None)
        out.append(
            ReportToolRun(
                tool_run_id=tool_run_id,
                tool_name=tool_name,
                status=status_raw,
                parser_status=parser_status,
                raw_artifact_ref=raw_artifact_ref,
                started_at=_str_or_none(get("started_at", None) or get("start_time", None)),
                finished_at=_str_or_none(get("finished_at", None) or get("end_time", None)),
                exit_code=int(exit_code) if isinstance(exit_code, int) else None,
                argv=_str_or_none(get("argv", None) or get("command", None)),
                sandbox_id=_str_or_none(get("sandbox_id", None)),
                source_ip=_str_or_none(get("source_ip", None)),
            )
        )
    return out


def _map_coverage(scan_report_data: Any) -> list[ReportCoverageItem]:
    """Map capability coverage into snapshot items.

    ``ScanReportData.coverage_occurrence`` is a *dict* (CONT-009 schema) whose
    ``coverage_by_capability`` maps ``capability_id -> serialized result``. The
    earlier implementation iterated it as a list, so real coverage was silently
    dropped and the snapshot rendered ``Coverage: not_assessed``. Handle the
    dict schema and keep the legacy list form for lightweight test doubles.
    """
    coverage = getattr(scan_report_data, "coverage_occurrence", None)
    items: list[dict[str, Any]] = []
    if isinstance(coverage, dict):
        by_cap = coverage.get("coverage_by_capability")
        if isinstance(by_cap, dict):
            items = [v for v in by_cap.values() if isinstance(v, dict)]
    elif isinstance(coverage, list):
        items = [v for v in coverage if isinstance(v, dict)]

    out: list[ReportCoverageItem] = []
    for item in items:
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


def _evidence_keys_by_finding(report_data: Any) -> dict[str, list[str]]:
    """Map ``finding_id -> [object_key]`` from persisted Evidence entries.

    Used to cross-link findings to their stored raw artifacts so the evidence
    gate can verify ``finding → evidence`` referential integrity.
    """
    out: dict[str, list[str]] = {}
    for entry in getattr(report_data, "evidence", None) or []:
        get = (
            entry.get if isinstance(entry, dict) else (lambda k, d=None, e=entry: getattr(e, k, d))
        )
        fid = get("finding_id")
        key = get("object_key")
        if fid and key:
            out.setdefault(str(fid), []).append(str(key))
    return out


def _map_evidence(report_data: Any) -> list[ReportEvidenceRef]:
    out: list[ReportEvidenceRef] = []
    for entry in getattr(report_data, "evidence", None) or []:
        get = (
            entry.get if isinstance(entry, dict) else (lambda k, d=None, e=entry: getattr(e, k, d))
        )
        object_key = get("object_key", None)
        finding_id = get("finding_id", None)
        eid = str(object_key or finding_id or f"E-{len(out) + 1}")
        out.append(
            ReportEvidenceRef(
                evidence_id=eid,
                kind=str(get("kind", "artifact") or "artifact"),
                object_key=str(object_key) if object_key else None,
                description=get("description", None),
                # Phase U (§30.1 item 5, R-16): integrity + provenance.
                sha256=_str_or_none(get("sha256", None) or get("hash", None)),
                size=(get("size", None) if isinstance(get("size", None), int) else None),
                mime=_str_or_none(get("mime", None) or get("content_type", None)),
                collected_at_utc=_str_or_none(
                    get("collected_at_utc", None) or get("created_at", None)
                ),
                collector=_str_or_none(get("collector", None) or get("producer_tool", None)),
                producer_tool_run_id=_str_or_none(
                    get("producer_tool_run_id", None) or get("tool_run_id", None)
                ),
                redaction_applied=(
                    bool(get("redaction_applied"))
                    if get("redaction_applied", None) is not None
                    else None
                ),
                chain_hash=_str_or_none(get("chain_hash", None)),
            )
        )
    return out


def _tools_executed(scan_report_data: Any) -> list[str]:
    runs = getattr(scan_report_data, "tool_runs", None) or []
    out: list[str] = []
    for run in runs:
        get = run.get if isinstance(run, dict) else (lambda k, d=None, r=run: getattr(r, k, d))
        name = str(get("tool_name", "") or get("tool", "") or "").strip()
        if name:
            out.append(name)
    return out


def _finding_dicts_for_wstg(report_data: Any) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in getattr(report_data, "findings", None) or []:
        get = f.get if isinstance(f, dict) else (lambda k, d=None, o=f: getattr(o, k, d))
        out.append(
            {
                "id": get("finding_id", None) or get("id", None) or get("stable_id", None),
                "title": get("title", "") or "",
                "description": get("description", "") or "",
                "tags": get("tags"),
                "references": get("references"),
                "ref": get("ref"),
                "wstg": get("wstg"),
                "owasp_wstg": get("owasp_wstg"),
                # Enable CWE / vuln_type → WSTG derivation so a finding that only
                # carries a CWE still counts toward the control it exercises.
                "cwe": get("cwe", None) or get("cwe_id", None),
                "vuln_type": get("vuln_type", None) or get("type", None),
                "category": get("category", None),
                # Evidence presence gates whether a finding's control-failure
                # counts toward coverage (ARGUS-WSTG-COV-1: no evidence → uncounted).
                "_has_evidence": bool(
                    (get("evidence_refs", None) or [])
                    or get("proof_of_concept", None)
                    or str(get("evidence_quality", "") or "").lower()
                    in {"weak", "moderate", "strong"}
                ),
            }
        )
    return out


def _build_wstg_block(
    report_data: Any,
    scan_report_data: Any,  # noqa: ARG001 - retained for signature/API compatibility
    *,
    scan_meta: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    """Evidence-based WSTG coverage snapshot (ARGUS-WSTG-COV-1), or None when off.

    Delegates to the single shared assembler (:func:`build_wstg_block`) so the
    snapshot, legacy pipeline dict, renderers and frontend all read one computed
    coverage. End-to-end path: findings → executions → evidence validation →
    per-test states → gate → snapshot.
    """
    if not settings.wstg_strict_gate_enabled:
        return None
    meta = scan_meta or {}
    scan_id = str(meta.get("scan_id") or getattr(report_data, "scan_id", "") or "unknown")
    target = str(meta.get("target") or getattr(report_data, "target", "") or "") or None
    scope_version = str(meta.get("scope_version") or "default")
    findings = _finding_dicts_for_wstg(report_data)
    evidence_entries = _evidence_entries_for_wstg(report_data)
    return build_wstg_block(
        findings,
        scan_id=scan_id,
        target=target,
        scope_version=scope_version,
        evidence_entries=evidence_entries,
    )


def _evidence_entries_for_wstg(report_data: Any) -> list[dict[str, Any]]:
    """Persisted evidence rows (finding_id + object_key + kind) for store-backed
    evidence validation (ARGUS-WSTG-COV-1 §Evidence)."""
    out: list[dict[str, Any]] = []
    for entry in getattr(report_data, "evidence", None) or []:
        get = (
            entry.get if isinstance(entry, dict) else (lambda k, d=None, e=entry: getattr(e, k, d))
        )
        fid = get("finding_id")
        object_key = get("object_key")
        if fid and object_key:
            out.append(
                {
                    "finding_id": str(fid),
                    "object_key": str(object_key),
                    "kind": str(get("kind", "") or ""),
                }
            )
    return out


def _host_of(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return "unknown"
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    return raw.split("/", 1)[0].split(":", 1)[0] or "unknown"


def _map_surface(report_data: Any, target: str) -> list[ReportSurfaceItem]:
    """Attack-surface inventory from technologies (+ target host).

    Structured port/service data, when present on the finding/recon layer, is folded
    in; otherwise each detected technology is attributed to the target host so the
    inventory is honest (technology observed on host) rather than fabricated.
    """
    host = _host_of(target)
    out: list[ReportSurfaceItem] = []
    seen: set[tuple[str, str | None]] = set()
    for tech in getattr(report_data, "technologies", None) or []:
        tech_str = str(tech).strip()
        if not tech_str:
            continue
        key = (host, tech_str)
        if key in seen:
            continue
        seen.add(key)
        out.append(ReportSurfaceItem(host=host, technology=tech_str))
    if not out:
        out.append(ReportSurfaceItem(host=host))
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

    evidence_by_finding = _evidence_keys_by_finding(report_data)
    findings = [
        _map_finding(
            f,
            i,
            evidence_keys=evidence_by_finding.get(
                str(getattr(f, "finding_id", None) or f"F-{i + 1}")
            ),
        )
        for i, f in enumerate(getattr(report_data, "findings", None) or [])
    ]

    tool_runs = _map_tool_runs(scan_report_data) if scan_report_data is not None else []
    coverage = _map_coverage(scan_report_data) if scan_report_data is not None else []
    evidence_refs = _map_evidence(report_data)

    not_assessed = [c.capability_id for c in coverage if c.status != "tested"]
    tested = [c.capability_id for c in coverage if c.status == "tested"]

    target = str(meta.get("target") or getattr(report_data, "target", "") or "")
    surface = _map_surface(report_data, target)

    # Phase K — attack narrative + impact chains (proven vs hypothetical, FND-03).
    attack_narrative = build_attack_narrative(findings)
    exploit_chains = build_exploit_chains(findings)
    # Phase L — engagement metadata for client log correlation.
    engagement = build_engagement_metadata(meta)
    engagement_arg = None if engagement_is_empty(engagement) else engagement

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
        wstg=_build_wstg_block(report_data, scan_report_data, scan_meta=meta),
        surface_inventory=surface,
        attack_narrative=attack_narrative,
        exploit_chains=exploit_chains,
        engagement=engagement_arg,
        generated_at=generated_at,
    )


__all__ = ["build_snapshot_from_report_data"]
