"""CONT-009 — coverage statuses and finding occurrences in report context."""

from __future__ import annotations

import importlib
import inspect
from datetime import UTC, datetime

import pytest
from src.capabilities.schemas import CoverageStatus
from src.findings.fingerprint import compute_finding_key, compute_occurrence_key
from src.findings.lifecycle import (
    FindingLifecycleService,
    FindingOccurrence,
    FindingState,
    LogicalFinding,
)
from src.reports.coverage_occurrence_context import (
    SCHEMA_VERSION,
    build_coverage_occurrence_context,
    derive_occurrences_from_findings,
)
from src.reports.valhalla_report_context import build_valhalla_report_context

_TENANT = "018f4a2e-7c8b-7b4d-8e0e-6b6579317431"
_SCAN = "018f4a2e-7c8b-7b4d-8e0e-6b6579317432"
_ENGAGEMENT = "018f4a2e-7c8b-7b4d-8e0e-6b6579317433"


def _finding_key() -> str:
    return compute_finding_key(
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        asset="https://app.example",
        category="xss",
        normalized_location="/search",
        parameter_or_component="q",
        root_cause_family="reflected_input",
    )


def _phase_outputs_with_coverage() -> list[tuple[str, dict]]:
    return [
        (
            "vuln_analysis",
            {
                "coverage_results": [
                    {
                        "requirement_id": "req-not-tested",
                        "capability_id": "web.application.xss",
                        "asset_id": "asset-1",
                        "status": CoverageStatus.NOT_TESTED.value,
                    },
                    {
                        "requirement_id": "req-covered-clean",
                        "capability_id": "web.application.sqli",
                        "asset_id": "asset-1",
                        "status": CoverageStatus.COVERED_NO_FINDING.value,
                        "execution_evidence_id": "evidence-sqlmap-run-1",
                    },
                ],
                "finding_occurrences": [
                    {
                        "occurrence_key": compute_occurrence_key(
                            finding_key=_finding_key(),
                            scanner="nuclei",
                            detector_id="xss-reflected",
                            detector_version="1.0.0",
                            request_signature="GET /search?q=1",
                            evidence_signal_hash="a" * 64,
                        ),
                        "finding_key": _finding_key(),
                        "tenant_id": _TENANT,
                        "scan_id": _SCAN,
                        "scanner": "nuclei",
                        "detector_id": "xss-reflected",
                        "detector_version": "1.0.0",
                        "evidence_refs": ("evidence-hash-1",),
                        "first_seen_at": datetime(2026, 8, 15, 12, 0, tzinfo=UTC),
                        "last_seen_at": datetime(2026, 8, 15, 12, 0, tzinfo=UTC),
                    }
                ],
                "logical_findings": {
                    _finding_key(): {
                        "finding_key": _finding_key(),
                        "tenant_id": _TENANT,
                        "engagement_id": _ENGAGEMENT,
                        "state": FindingState.MACHINE_VALIDATED.value,
                        "title": "Reflected XSS",
                        "category": "xss",
                        "occurrence_keys": [
                            compute_occurrence_key(
                                finding_key=_finding_key(),
                                scanner="nuclei",
                                detector_id="xss-reflected",
                                detector_version="1.0.0",
                                request_signature="GET /search?q=1",
                                evidence_signal_hash="a" * 64,
                            )
                        ],
                    }
                },
            },
        )
    ]


def test_not_tested_and_covered_no_finding_are_distinct_in_context():
    ctx = build_coverage_occurrence_context(
        tenant_id=_TENANT,
        scan_id=_SCAN,
        phase_outputs=_phase_outputs_with_coverage(),
        engagement_id=_ENGAGEMENT,
    )

    counts = ctx["coverage_status_counts"]
    assert counts[CoverageStatus.NOT_TESTED.value] == 1
    assert counts[CoverageStatus.COVERED_NO_FINDING.value] == 1
    assert CoverageStatus.NOT_TESTED.value != CoverageStatus.COVERED_NO_FINDING.value

    by_cap = ctx["coverage_by_capability"]
    assert by_cap["web.application.xss"]["status"] == CoverageStatus.NOT_TESTED.value
    assert by_cap["web.application.xss"]["not_tested"] is True
    assert by_cap["web.application.xss"]["honest_no_finding"] is False

    assert by_cap["web.application.sqli"]["status"] == CoverageStatus.COVERED_NO_FINDING.value
    assert by_cap["web.application.sqli"]["honest_no_finding"] is True
    assert by_cap["web.application.sqli"]["not_tested"] is False
    assert by_cap["web.application.sqli"]["execution_evidence_id"] == "evidence-sqlmap-run-1"

    assert ctx["totals"]["not_tested"] == 1
    assert ctx["totals"]["covered_no_finding"] == 1


def test_occurrences_referenced_by_key_hash():
    ctx = build_coverage_occurrence_context(
        tenant_id=_TENANT,
        scan_id=_SCAN,
        phase_outputs=_phase_outputs_with_coverage(),
        engagement_id=_ENGAGEMENT,
    )

    finding_key = _finding_key()
    assert len(finding_key) == 64
    assert finding_key in ctx["logical_findings"]
    assert finding_key in ctx["occurrence_index"]

    occ_keys = ctx["occurrence_index"][finding_key]
    assert len(occ_keys) == 1
    occ_key = occ_keys[0]
    assert len(occ_key) == 64
    assert occ_key in ctx["occurrences_by_key"]
    assert ctx["occurrences_by_key"][occ_key]["finding_key"] == finding_key
    assert ctx["logical_findings"][finding_key]["occurrence_keys"] == [occ_key]


def test_report_path_has_no_finding_deletion_api():
    module = importlib.import_module("src.reports.coverage_occurrence_context")
    forbidden = ("delete", "remove", "purge", "erase")
    for name, obj in inspect.getmembers(module):
        if name.startswith("_"):
            continue
        lowered = name.lower()
        assert not any(token in lowered for token in forbidden), (
            f"coverage_occurrence_context must not expose deletion API: {name}"
        )

    service = FindingLifecycleService()
    with pytest.raises(RuntimeError, match="finding_deletion_forbidden"):
        service.delete_finding(
            LogicalFinding(
                finding_key=_finding_key(),
                tenant_id=_TENANT,
                engagement_id=_ENGAGEMENT,
            )
        )

    ctx_invariant = build_coverage_occurrence_context(
        tenant_id=_TENANT,
        scan_id=_SCAN,
        phase_outputs=_phase_outputs_with_coverage(),
    )
    assert ctx_invariant["invariants"]["finding_deletion_forbidden"] is True


def test_dishonest_covered_no_finding_downgraded_without_evidence():
    ctx = build_coverage_occurrence_context(
        tenant_id=_TENANT,
        scan_id=_SCAN,
        phase_outputs=[
            (
                "vuln_analysis",
                {
                    "coverage_results": [
                        {
                            "requirement_id": "req-false-clean",
                            "capability_id": "web.application.xss",
                            "asset_id": "asset-1",
                            "status": CoverageStatus.COVERED_NO_FINDING.value,
                        },
                    ],
                },
            )
        ],
        engagement_id=_ENGAGEMENT,
    )
    by_cap = ctx["coverage_by_capability"]
    assert by_cap["web.application.xss"]["status"] == CoverageStatus.NOT_TESTED.value
    assert ctx["totals"]["not_tested"] == 1
    assert ctx["totals"]["covered_no_finding"] == 0


def test_report_quality_gate_payload_distinguishes_coverage_statuses():
    from types import SimpleNamespace

    from src.reports.report_quality_gate import build_report_quality_gate

    coverage_ctx = build_coverage_occurrence_context(
        tenant_id=_TENANT,
        scan_id=_SCAN,
        phase_outputs=_phase_outputs_with_coverage(),
        engagement_id=_ENGAGEMENT,
    )
    data = SimpleNamespace(
        valhalla_context=SimpleNamespace(coverage_occurrence=coverage_ctx),
        findings=[],
        scan=None,
        report=None,
    )
    gate = build_report_quality_gate(data)
    payload = gate.as_dict()
    cap_cov = payload["capability_coverage"]
    assert cap_cov["not_tested"] == 1
    assert cap_cov["covered_no_finding"] == 1
    assert cap_cov["not_tested_distinct_from_covered_no_finding"] is True
    assert cap_cov["absence_of_finding_is_not_coverage"] is True
    assert cap_cov["status_counts"]["not_tested"] == 1
    assert cap_cov["status_counts"]["covered_no_finding"] == 1


def test_valhalla_report_context_includes_coverage_occurrence_block():
    valhalla = build_valhalla_report_context(
        tenant_id=_TENANT,
        scan_id=_SCAN,
        recon_results=None,
        tech_profile=None,
        anomalies_structured=None,
        raw_artifact_keys=[],
        phase_outputs=_phase_outputs_with_coverage(),
        phase_inputs=[],
        findings=[],
        report_technologies=None,
        fetch_raw_bodies=False,
    )

    block = valhalla.coverage_occurrence
    assert block.get("schema_version") == SCHEMA_VERSION
    assert block["totals"]["coverage_results"] == 2
    assert block["coverage_by_capability"]["web.application.xss"]["status"] == "not_tested"


def test_derive_occurrences_from_findings_uses_stable_keys():
    finding_key = _finding_key()
    logical, occurrences = derive_occurrences_from_findings(
        [
            {
                "finding_key": finding_key,
                "title": "Reflected XSS",
                "category": "xss",
                "affected_url": "https://app.example/search?q=1",
                "scanner": "nuclei",
                "detector_id": "xss-reflected",
                "proof_of_concept": {"payload": "<script>"},
            }
        ],
        tenant_id=_TENANT,
        scan_id=_SCAN,
        engagement_id=_ENGAGEMENT,
    )

    assert finding_key in logical
    assert len(occurrences) == 1
    occ = next(iter(occurrences.values()))
    assert occ.finding_key == finding_key
    assert len(occ.occurrence_key) == 64
    assert occ.occurrence_key in logical[finding_key].occurrence_keys


def test_coverage_context_merges_persisted_when_phase_blobs_empty() -> None:
    finding_key = _finding_key()
    occ_key = compute_occurrence_key(
        finding_key=finding_key,
        scanner="nuclei",
        detector_id="xss-reflected",
        detector_version="1.0.0",
        request_signature="GET /search?q=1",
        evidence_signal_hash="b" * 64,
    )
    now = datetime(2026, 8, 16, 9, 0, tzinfo=UTC)
    finding = LogicalFinding(
        finding_key=finding_key,
        tenant_id=_TENANT,
        engagement_id=_ENGAGEMENT,
        title="Persisted XSS",
        category="xss",
        occurrence_keys=[occ_key],
    )
    occurrence = FindingOccurrence(
        occurrence_key=occ_key,
        finding_key=finding_key,
        tenant_id=_TENANT,
        scan_id=_SCAN,
        scanner="nuclei",
        detector_id="xss-reflected",
        detector_version="1.0.0",
        first_seen_at=now,
        last_seen_at=now,
    )
    ctx = build_coverage_occurrence_context(
        tenant_id=_TENANT,
        scan_id=_SCAN,
        phase_outputs=[],
        persisted_logical_findings={finding_key: finding},
        persisted_occurrences={occ_key: occurrence},
    )
    assert ctx["totals"]["logical_findings"] == 1
    assert ctx["totals"]["occurrences"] == 1
    assert ctx["logical_findings"][finding_key]["title"] == "Persisted XSS"
