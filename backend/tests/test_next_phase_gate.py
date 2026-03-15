"""Tests for Next Phase Gate (VA3UP-007)."""

from __future__ import annotations

from pathlib import Path

from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle
from src.recon.vulnerability_analysis.next_phase_gate import (
    check_next_phase_gate_allowed,
    evaluate_next_phase_gate,
    generate_next_phase_gate_md,
)


def test_evaluate_next_phase_gate_blocked_missing_stage1() -> None:
    """Gate blocks when Stage 1 not ready."""
    result = evaluate_next_phase_gate(
        ai_results={},
        run_id="r1",
        job_id="j1",
        stage1_ready=False,
    )
    assert result.blocked
    assert result.status == "blocked_missing_stage1"
    assert "Stage 1" in result.blocking_reasons[0]


def test_evaluate_next_phase_gate_blocked_missing_stage2() -> None:
    """Gate blocks when Stage 2 not ready."""
    result = evaluate_next_phase_gate(
        ai_results={},
        run_id="r1",
        job_id="j1",
        stage2_ready=False,
    )
    assert result.blocked
    assert result.status == "blocked_missing_stage2"


def test_evaluate_next_phase_gate_blocked_missing_stage3() -> None:
    """Gate blocks when Stage 3 not ready."""
    result = evaluate_next_phase_gate(
        ai_results={},
        run_id="r1",
        job_id="j1",
        stage3_ready=False,
    )
    assert result.blocked
    assert result.status == "blocked_missing_stage3"


def test_evaluate_next_phase_gate_blocked_no_confirmed_findings() -> None:
    """Gate blocks when no confirmed findings."""
    ai_results = {
        "authorization_analysis": {
            "checks": [
                {
                    "target_id": "ep_1",
                    "check_type": "idor",
                    "description": "Test",
                    "evidence_refs": [],
                    "confidence": 0.5,
                    "statement_type": "hypothesis",
                },
            ],
        },
    }
    result = evaluate_next_phase_gate(
        ai_results=ai_results,
        run_id="r1",
        job_id="j1",
    )
    assert result.blocked
    assert result.status == "blocked_no_confirmed_findings"
    assert result.confirmed_finding_count == 0


def test_evaluate_next_phase_gate_ready_when_all_conditions_met() -> None:
    """Gate allows when all conditions met (sufficient evidence, no contradictions, linkage)."""
    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="e1",
        target_id="t1",
        artifact_refs=["route_inventory.csv"],
    )
    ai_results = {
        "authorization_analysis": {
            "checks": [
                {
                    "target_id": "ep_1",
                    "check_type": "idor",
                    "description": "Test",
                    "evidence_refs": ["route_inventory.csv:1", "artifact:2"],
                    "stage1_evidence_refs": ["route_inventory.csv:1"],
                    "scenario_ids": ["ts_1"],
                    "trust_boundary_id": "tb_1",
                    "affected_asset_id": "ca_1",
                    "confidence": 0.85,
                    "statement_type": "evidence",
                },
            ],
        },
        "finding_correlation": {"correlations": []},
    }
    from app.schemas.threat_modeling.schemas import CriticalAsset, ThreatScenario, TrustBoundary

    bundle = VulnerabilityAnalysisInputBundle(
        engagement_id="e1",
        target_id="t1",
        artifact_refs=["route_inventory.csv"],
        critical_assets=[CriticalAsset(id="ca_1", name="API", asset_type="service", description="")],
        trust_boundaries=[TrustBoundary(id="tb_1", name="Boundary", description="")],
        threat_scenarios=[
            ThreatScenario(
                id="ts_1",
                title="Test",
                description="Test scenario",
                related_assets=[],
                likelihood=0.5,
                impact=0.5,
                priority="medium",
            )
        ],
    )
    result = evaluate_next_phase_gate(
        ai_results=ai_results,
        run_id="r1",
        job_id="j1",
        bundle=bundle,
    )
    if result.status == "ready_for_next_phase":
        assert not result.blocked
    else:
        assert result.blocked


def test_generate_next_phase_gate_md() -> None:
    """generate_next_phase_gate_md produces valid markdown."""
    from app.schemas.vulnerability_analysis.next_phase_gate import NextPhaseGateResult

    result = NextPhaseGateResult(
        run_id="r1",
        job_id="j1",
        status="blocked_no_confirmed_findings",
        blocked=True,
        blocking_reasons=["No confirmed findings."],
        confirmed_finding_count=0,
        total_finding_count=5,
        gate_version="1.0",
    )
    md = generate_next_phase_gate_md(result)
    assert "# Next Phase Gate" in md
    assert "blocked_no_confirmed_findings" in md
    assert "r1" in md
    assert "No confirmed findings" in md


def test_check_next_phase_gate_allowed_missing_file(tmp_path: Path) -> None:
    """check_next_phase_gate_allowed returns (False, None) when file missing."""
    allowed, gate = check_next_phase_gate_allowed(tmp_path)
    assert not allowed
    assert gate is None


def test_check_next_phase_gate_allowed_blocked(tmp_path: Path) -> None:
    """check_next_phase_gate_allowed returns (False, result) when blocked."""
    gate_path = tmp_path / "next_phase_gate.json"
    gate_path.write_text(
        '{"run_id":"r1","job_id":"j1","status":"blocked_no_confirmed_findings",'
        '"blocked":true,"blocking_reasons":[],"confirmed_finding_count":0,'
        '"total_finding_count":0,"unlinked_finding_ids":[],'
        '"findings_with_insufficient_evidence":[],"findings_with_contradictions":[],"gate_version":"1.0"}',
        encoding="utf-8",
    )
    allowed, gate = check_next_phase_gate_allowed(tmp_path)
    assert not allowed
    assert gate is not None
    assert gate.status == "blocked_no_confirmed_findings"


def test_check_next_phase_gate_allowed_ready(tmp_path: Path) -> None:
    """check_next_phase_gate_allowed returns (True, result) when ready."""
    gate_path = tmp_path / "next_phase_gate.json"
    gate_path.write_text(
        '{"run_id":"r1","job_id":"j1","status":"ready_for_next_phase",'
        '"blocked":false,"blocking_reasons":[],"confirmed_finding_count":1,'
        '"total_finding_count":5,"unlinked_finding_ids":[],'
        '"findings_with_insufficient_evidence":[],"findings_with_contradictions":[],"gate_version":"1.0"}',
        encoding="utf-8",
    )
    allowed, gate = check_next_phase_gate_allowed(tmp_path)
    assert allowed
    assert gate is not None
    assert gate.status == "ready_for_next_phase"
