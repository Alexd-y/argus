"""Phase 16 — Valhalla completeness registry + VP regression validators."""

from __future__ import annotations

from src.reports.valhalla_completeness import (
    VALHALLA_REQUIRED_SOURCES,
    find_stop_list_violations,
    unclassified_findings_in_registry,
    valhalla_release_blockers,
    validate_valhalla_completeness,
)


def _blockers(**over):
    kwargs = {
        "snapshot": {},
        "sections": {},
        "report_text": "",
        "findings": [],
        "requested_tier": "valhalla",
        "actual_tier": "valhalla",
        "llm_analysis_status": "completed",
    }
    kwargs.update(over)
    return valhalla_release_blockers(**kwargs)


def test_release_ok_when_all_clean() -> None:
    assert _blockers() == []


def test_release_blocks_on_tier_swap() -> None:
    blockers = _blockers(actual_tier="midgard")
    assert any("VP-01" in b for b in blockers)


def test_release_blocks_on_placeholder() -> None:
    blockers = _blockers(report_text="PoC details are available in Asgard / Valhalla reports.")
    assert any("VP-02" in b for b in blockers)


def test_release_blocks_on_incomplete_llm() -> None:
    blockers = _blockers(llm_analysis_status="failed")
    assert any("LLM analysis not complete" in b for b in blockers)


def test_release_blocks_on_source_section_mismatch() -> None:
    blockers = _blockers(snapshot={"tech_stack": ["nginx"]}, sections={"surface_inventory": ""})
    assert any("VP-04" in b for b in blockers)


# --- VP-04: source non-empty but section empty = release error ---------------


def test_vp04_nonempty_source_empty_section_is_violation() -> None:
    snapshot = {"tech_stack": [{"name": "whatweb", "value": "nginx"}], "findings": [{"id": "f1"}]}
    sections = {"surface_inventory": "", "findings_registry": "…rendered…"}
    report = validate_valhalla_completeness(snapshot, sections)
    assert not report.ok
    keys = {v.source_key for v in report.violations}
    assert "tech_stack" in keys  # tech present but surface_inventory empty
    assert "findings" not in keys  # findings present and section rendered


def test_vp04_all_sections_present_is_ok() -> None:
    snapshot = {"findings": [{"id": "f1"}], "tech_stack": ["nginx"]}
    sections = {"findings_registry": "x", "surface_inventory": "y"}
    report = validate_valhalla_completeness(snapshot, sections)
    # other required sources are empty on both sides → not violations
    assert report.ok


def test_vp04_empty_source_empty_section_not_violation() -> None:
    report = validate_valhalla_completeness({"tech_stack": []}, {"surface_inventory": ""})
    assert report.ok


# --- VP-02: placeholder stop-list --------------------------------------------


def test_vp02_stop_list_detected() -> None:
    text = "See the finding. PoC details are available in Asgard / Valhalla reports."
    violations = find_stop_list_violations(text)
    assert violations


def test_vp02_clean_text_passes() -> None:
    assert find_stop_list_violations("A working PoC is attached in the evidence appendix.") == []


# --- VP-05: unclassified observations must not sit in the findings registry ---


def test_vp05_unclassified_flagged() -> None:
    findings = [
        {"title": "SQL injection", "cwe": "CWE-89", "category": "injection", "description": "…"},
        {
            "title": "Unclassified observation",
            "cwe": "not_assessed",
            "description": "cannot be interpreted",
        },
    ]
    offenders = unclassified_findings_in_registry(findings)
    assert len(offenders) == 1
    assert offenders[0]["title"] == "Unclassified observation"


def test_vp05_real_findings_not_flagged() -> None:
    findings = [{"title": "XSS", "cwe": "CWE-79", "category": "xss", "description": "reflected"}]
    assert unclassified_findings_in_registry(findings) == []


# --- registry shape ----------------------------------------------------------


def test_required_sources_cover_key_areas() -> None:
    keys = {s.key for s in VALHALLA_REQUIRED_SOURCES}
    assert {"findings", "tool_runs", "ports_services", "tech_stack", "exploitation"} <= keys
    # Cairn sections are optional (not_applicable when engine unused).
    cairn = [s for s in VALHALLA_REQUIRED_SOURCES if s.key.startswith("cairn_")]
    assert cairn and all(not s.required for s in cairn)
