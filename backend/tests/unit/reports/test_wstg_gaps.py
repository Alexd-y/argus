"""ARGUS-WSTG-COV-1 — remaining honesty scenarios (spec §14: 2, 3, 4, 7, 15, 25)
plus store-backed evidence, reason codes, catalog-checksum drift and legacy
snapshot rendering.

These close the gaps left after the first refactor pass. Every assertion is
about *verified facts*, never an arbitrary coverage threshold.
"""

from __future__ import annotations

from src.reports.renderers import render_html, render_markdown
from src.reports.report_document import build_report_document
from src.reports.wstg_applicability import (
    _MANUAL_REQUIRED_TESTS,
    _UNSUPPORTED_TESTS,
    decide_applicability,
)
from src.reports.wstg_gate import IntegrityCode, compute_wstg_coverage
from src.reports.wstg_model import Applicability, ReasonCode, Scope
from src.reports.wstg_plan import build_wstg_states, catalog_checksum, catalog_ids
from src.reports.wstg_report import build_wstg_block
from src.reports.wstg_surface import (
    DiscoveryStatus,
    SurfaceFeature,
    SurfaceObservation,
    SurfaceState,
)

_AUTH_DEPENDENT = "WSTG-ATHN-02"  # requires an auth mechanism surface
_UPLOAD_DEPENDENT = "WSTG-BUSL-08"  # requires a file-upload surface


def _obs(feature, state, *, discovery, evidence=()):
    return SurfaceObservation(
        feature=feature,
        state=state,
        scan_id="scan-1",
        target_ref="https://t.example",
        discovery_status=discovery,
        evidence_refs=tuple(evidence),
    )


# --------------------------------------------------------------------------- #
# §14.2 — a tool that never ran does not make the surface "absent".
# --------------------------------------------------------------------------- #
def test_scenario2_no_surface_data_keeps_dependent_test_unknown():
    # No observations at all (no discovery ran).
    decisions = decide_applicability(surface=[])
    d = decisions[_UPLOAD_DEPENDENT]
    assert d.state == Applicability.UNKNOWN
    assert d.is_valid_not_applicable() is False


# --------------------------------------------------------------------------- #
# §14.3 — a failed/incomplete discovery yields unknown, never absent.
# --------------------------------------------------------------------------- #
def test_scenario3_discovery_timeout_is_unknown_not_absent():
    surface = [
        _obs(
            SurfaceFeature.FILE_UPLOAD,
            SurfaceState.ABSENT,  # claims absent...
            discovery=DiscoveryStatus.FAILED,  # ...but discovery failed → not trusted
            evidence=("ev-x",),
        )
    ]
    decisions = decide_applicability(surface=surface)
    d = decisions[_UPLOAD_DEPENDENT]
    assert d.state == Applicability.UNKNOWN
    assert d.reason_code == ReasonCode.DISCOVERY_INCOMPLETE


# --------------------------------------------------------------------------- #
# §14.4 — a confirmed absence in scope, with evidence, is a valid N/A.
# --------------------------------------------------------------------------- #
def test_scenario4_confirmed_absence_is_valid_na():
    surface = [
        _obs(
            SurfaceFeature.FILE_UPLOAD,
            SurfaceState.ABSENT,
            discovery=DiscoveryStatus.COMPLETE,
            evidence=("ev-crawl-1",),
        )
    ]
    decisions = decide_applicability(surface=surface, scope_version="v7")
    d = decisions[_UPLOAD_DEPENDENT]
    assert d.state == Applicability.NOT_APPLICABLE
    assert d.reason_code == ReasonCode.FEATURE_ABSENT
    assert d.is_valid_not_applicable() is True
    assert d.scope_version == "v7"


def test_scenario4_valid_na_removed_from_denominator():
    surface = [
        _obs(
            SurfaceFeature.FILE_UPLOAD,
            SurfaceState.ABSENT,
            discovery=DiscoveryStatus.COMPLETE,
            evidence=("ev-crawl-1",),
        )
    ]
    decisions = decide_applicability(surface=surface)
    states = build_wstg_states(decisions=decisions)
    report = compute_wstg_coverage(
        states, catalog_ids=catalog_ids(), catalog_checksum=catalog_checksum()
    )
    assert report.validated_not_applicable >= 2  # BUSL-08 + BUSL-09 share the req
    assert report.denominator == report.in_scope_total - report.validated_not_applicable


# --------------------------------------------------------------------------- #
# §14.7 — out_of_scope is distinct from N/A and carries a scope version.
# --------------------------------------------------------------------------- #
def test_scenario7_out_of_scope_distinct_from_na():
    decisions = decide_applicability()
    states = build_wstg_states(decisions=decisions, out_of_scope_ids=frozenset({"WSTG-CLNT-10"}))
    oos = next(s for s in states if s.test_id == "WSTG-CLNT-10")
    assert oos.scope == Scope.OUT_OF_SCOPE
    report = compute_wstg_coverage(
        states,
        catalog_ids=catalog_ids(),
        catalog_checksum=catalog_checksum(),
        scope_version="scope-9",
    )
    assert report.out_of_scope >= 1
    assert report.scope_version == "scope-9"
    # Out-of-scope is not counted as a validated N/A.
    assert report.in_scope_total == report.catalog_total - report.out_of_scope


# --------------------------------------------------------------------------- #
# §14.15 — removing the stored artifact never raises counted/coverage.
# --------------------------------------------------------------------------- #
_EVIDENCED_FINDING = {
    "id": "F1",
    "title": "SQL injection",
    "vuln_type": "sqli",
    "cwe": "CWE-89",
    "_has_evidence": True,
}


def test_scenario15_store_backed_missing_artifact_not_counted():
    # Store holds NO artifact for the finding → not validated → not counted.
    block = build_wstg_block(
        [_EVIDENCED_FINDING],
        scan_id="scan-1",
        target="https://t.example",
        evidence_entries=[],  # store-backed, but empty
    )
    assert block["counted"] == 0

    # Same finding, but now the store actually holds an artifact → counted.
    block2 = build_wstg_block(
        [_EVIDENCED_FINDING],
        scan_id="scan-1",
        target="https://t.example",
        evidence_entries=[
            {"finding_id": "F1", "object_key": "s3://ev/F1.json", "kind": "tool_output"}
        ],
    )
    assert block2["counted"] >= 1


# --------------------------------------------------------------------------- #
# §14.25 — losing a tool while scope/surface are unchanged never raises coverage.
# --------------------------------------------------------------------------- #
def test_scenario25_tool_loss_does_not_raise_coverage():
    # Baseline: one evidenced finding + stored artifact.
    entries = [{"finding_id": "F1", "object_key": "k", "kind": "tool_output"}]
    before = build_wstg_block(
        [_EVIDENCED_FINDING], scan_id="scan-1", target="t", evidence_entries=entries
    )
    # "Tool lost" → the finding is no longer produced, surface unchanged.
    after = build_wstg_block([], scan_id="scan-1", target="t", evidence_entries=[])
    assert after["counted"] <= before["counted"]
    assert after["denominator"] == before["denominator"]  # scope/surface unchanged


# --------------------------------------------------------------------------- #
# §7 — manual/unsupported tests stay in the denominator with an explicit reason.
# --------------------------------------------------------------------------- #
def test_manual_required_stays_in_denominator_with_reason():
    decisions = decide_applicability()
    tid = next(iter(_MANUAL_REQUIRED_TESTS))
    d = decisions[tid]
    assert d.reason_code == ReasonCode.MANUAL_REQUIRED
    assert d.state in (Applicability.APPLICABLE, Applicability.UNKNOWN)
    assert d.is_valid_not_applicable() is False  # never silently excluded


def test_unsupported_stays_in_denominator_with_reason():
    decisions = decide_applicability()
    tid = next(iter(_UNSUPPORTED_TESTS))
    d = decisions[tid]
    assert d.reason_code == ReasonCode.UNSUPPORTED
    assert d.is_valid_not_applicable() is False


# --------------------------------------------------------------------------- #
# §11 — a catalog checksum mismatch invalidates the gate.
# --------------------------------------------------------------------------- #
def test_catalog_checksum_mismatch_invalidates_gate():
    decisions = decide_applicability()
    states = build_wstg_states(decisions=decisions)
    report = compute_wstg_coverage(
        states,
        catalog_ids=catalog_ids(),
        catalog_checksum=catalog_checksum(),
        expected_catalog_checksum="deadbeef-not-the-real-checksum",
    )
    assert report.evidence_integrity_passed is False
    assert report.coverage_pct is None
    codes = {e.code for e in report.integrity_errors}
    assert IntegrityCode.CATALOG_CHECKSUM_MISMATCH in codes


# --------------------------------------------------------------------------- #
# §13 — the block carries versions + decisions + surface for auditability.
# --------------------------------------------------------------------------- #
def test_block_carries_versions_and_decisions():
    block = build_wstg_block([], scan_id="scan-1", target="t")
    assert block["applicability_rules_version"]
    assert block["scenario_registry_version"]
    assert isinstance(block["decisions"], list) and block["decisions"]
    assert isinstance(block["surface"], list)
    # Every decision is auditable (has a rule id + version).
    for d in block["decisions"]:
        assert d["rule_id"]
        assert d["rule_version"]


# --------------------------------------------------------------------------- #
# §14.29 / §13 — a legacy snapshot (no schema_version) renders as unverified.
# --------------------------------------------------------------------------- #
def _legacy_doc():
    return build_report_document(
        scan_id="s1",
        tenant_id="t1",
        target="example.com",
        wstg={  # legacy shape: only a percentage, no schema_version
            "wstg_version": "4.2",
            "coverage_pct": 82.0,
            "gate_passed": True,
        },
    )


def test_legacy_snapshot_marked_unverified_in_html_and_md():
    doc = _legacy_doc()
    html = render_html(doc)
    md = render_markdown(doc)
    assert "legacy / unverified" in html
    assert "legacy / unverified" in md
