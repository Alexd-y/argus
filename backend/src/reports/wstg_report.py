"""Single WSTG coverage block assembler (ARGUS-WSTG-COV-1).

Both the canonical snapshot (``snapshot_builder``) and the legacy pipeline dict
(``orchestration.handlers``) build their ``wstg`` block through this one
function, so every renderer and the frontend read *the same* computed coverage
instead of two divergent heuristics (spec §13).

Pipeline: findings → executions → evidence validation → per-test states → gate →
snapshot dict (aggregates + verdict + full per-test table + decisions).
"""

from __future__ import annotations

from typing import Any

from src.reports.wstg_applicability import RULE_VERSION, decide_applicability
from src.reports.wstg_coverage import wstg_ids_for_finding
from src.reports.wstg_evidence import any_validated, validate_evidence
from src.reports.wstg_execution import aggregate_executions
from src.reports.wstg_gate import compute_wstg_coverage
from src.reports.wstg_plan import build_wstg_states, catalog_checksum, catalog_ids
from src.reports.wstg_producers import (
    ReportDataEvidenceResolver,
    findings_to_executions,
)
from src.reports.wstg_surface import (
    DiscoveryStatus,
    SurfaceFeature,
    SurfaceObservation,
    SurfaceState,
)

# Version of the scenario registry the coverage block is computed against. The
# per-scenario model is not yet fully materialised (test-level coverage only),
# so this is surfaced for forward-compat and drift detection (spec §13).
SCENARIO_REGISTRY_VERSION = "argus-wstg-scn-0"

# Features without a dedicated discovery detector default to ``unknown`` (kept in
# the denominator) — running a tool is never proof of presence/absence (§Surface).
_UNOBSERVED_SURFACE_FEATURES: tuple[SurfaceFeature, ...] = (
    SurfaceFeature.FORMS,
    SurfaceFeature.QUERY_PARAMS,
    SurfaceFeature.PATH_PARAMS,
    SurfaceFeature.BODY_INPUTS,
    SurfaceFeature.COOKIES,
    SurfaceFeature.AUTH_MECHANISM,
    SurfaceFeature.CONFIRMED_SESSION,
    SurfaceFeature.CONFIRMED_ROLES,
    SurfaceFeature.FILE_UPLOAD,
    SurfaceFeature.API,
    SurfaceFeature.WEBSOCKETS,
    SurfaceFeature.CLIENT_INPUT,
)


def _default_surface(
    *, scan_id: str, target: str | None, scope_version: str | None
) -> list[SurfaceObservation]:
    return [
        SurfaceObservation(
            feature=feature,
            state=SurfaceState.UNKNOWN,
            scan_id=scan_id,
            target_ref=target,
            scope_ref=scope_version,
            discovery_status=DiscoveryStatus.NOT_ATTEMPTED,
            limitations=("no dedicated surface-discovery detector",),
        )
        for feature in _UNOBSERVED_SURFACE_FEATURES
    ]


def build_wstg_block(
    findings: list[dict[str, Any]],
    *,
    scan_id: str,
    target: str | None,
    scope_version: str = "default",
    surface: list[SurfaceObservation] | None = None,
    evidence_entries: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Compute the canonical WSTG coverage block from finding facts.

    ``findings`` are normalised dicts carrying at least ``id``, wstg/cwe/vuln_type
    hints and ``_has_evidence``.

    ``evidence_entries`` are the persisted evidence rows (``finding_id`` +
    ``object_key`` + ``kind``). When supplied, evidence validation is
    *store-backed*: a finding only counts if the store actually holds an artifact
    for it (spec §Evidence). When omitted, the ``_has_evidence`` flag is used.
    """
    executions = findings_to_executions(
        findings,
        scan_id=scan_id,
        target=target,
        wstg_ids_for_finding=wstg_ids_for_finding,
    )
    aggregated = aggregate_executions(executions)

    resolver = ReportDataEvidenceResolver(
        findings, scan_id=scan_id, target=target, evidence_entries=evidence_entries
    )
    all_refs = sorted({ref for agg in aggregated.values() for ref in agg.evidence_refs})
    resolved = resolver.resolve(all_refs)
    validations = validate_evidence(resolved, expected_scan_id=scan_id, expected_target=target)
    evidence_validated_by_test = {
        test_id: any_validated({r: validations[r] for r in agg.evidence_refs if r in validations})
        for test_id, agg in aggregated.items()
    }

    finding_test_ids = frozenset(
        wid for f in findings if f.get("_has_evidence") for wid in wstg_ids_for_finding(f)
    )
    surface_obs = (
        surface
        if surface is not None
        else _default_surface(scan_id=scan_id, target=target, scope_version=scope_version)
    )
    decisions = decide_applicability(
        surface=surface_obs,
        finding_test_ids=finding_test_ids,
        scope_version=scope_version,
    )

    states = build_wstg_states(
        decisions=decisions,
        aggregated=aggregated,
        evidence_validated_by_test=evidence_validated_by_test,
    )
    report = compute_wstg_coverage(
        states,
        catalog_ids=catalog_ids(),
        catalog_checksum=catalog_checksum(),
        scope_version=scope_version,
    )

    block = report.as_dict()
    block["scope_version"] = scope_version
    block["scenario_registry_version"] = SCENARIO_REGISTRY_VERSION
    block["applicability_rules_version"] = RULE_VERSION
    block["tests"] = [
        {
            "test_id": s.test_id,
            "category": s.category,
            "scope": s.scope.value,
            "applicability": s.applicability.value,
            "applicability_valid": s.applicability_valid,
            "reason_code": s.reason_code.value if s.reason_code else None,
            "rationale": s.rationale,
            "execution_status": s.execution_status.value,
            "outcome": s.outcome.value,
            "evidence_refs": list(s.evidence_refs),
            "evidence_validated": s.evidence_validated,
            "required_scenarios_completed": s.required_scenarios_completed,
            "completion_criteria_met": s.completion_criteria_met,
            "conflict": s.conflict,
            "counts": s.counts_toward_coverage(),
            "scenario_ids": list(s.scenario_ids),
        }
        for s in states
    ]
    block["executions"] = [
        {
            "test_id": e.test_id,
            "scenario_id": e.scenario_id,
            "executor": e.executor,
            "execution_status": e.execution_status.value,
            "outcome": e.outcome.value,
            "evidence_refs": list(e.evidence_refs),
            "limitations": list(e.limitations),
        }
        for e in executions
    ]
    # Auditable applicability decisions (rule + version + evidence) — the gate's
    # N/A justifications must be inspectable, not just an aggregate count (§13).
    block["decisions"] = [
        {
            "test_id": d.test_id,
            "state": d.state.value,
            "reason_code": d.reason_code.value if d.reason_code else None,
            "rationale": d.rationale,
            "evidence_refs": list(d.evidence_refs),
            "rule_id": d.rule_id,
            "rule_version": d.rule_version,
            "scope_version": d.scope_version,
            "source": d.source,
        }
        for d in decisions.values()
    ]
    # Structured surface observations feeding the applicability decisions (§6).
    block["surface"] = [
        {
            "feature": o.feature.value,
            "state": o.state.value,
            "discovery_status": o.discovery_status.value,
            "evidence_refs": list(o.evidence_refs),
            "limitations": list(o.limitations),
        }
        for o in surface_obs
    ]
    return block


__all__ = ["build_wstg_block"]
