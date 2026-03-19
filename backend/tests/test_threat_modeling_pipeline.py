"""Tests for threat modeling pipeline (TM-006)."""

from __future__ import annotations

from pathlib import Path

import pytest
from src.recon.threat_modeling.dependency_check import STAGE1_BASELINE_ARTIFACTS
from src.recon.threat_modeling.pipeline import (
    ThreatModelPipelineError,
    execute_threat_modeling_run,
)


@pytest.fixture
def complete_recon_dir(tmp_path: Path) -> Path:
    """Create recon dir with all required Stage 1 artifacts."""
    for filename in STAGE1_BASELINE_ARTIFACTS:
        (tmp_path / filename).write_text("{}")
    (tmp_path / "stage2_structured.json").write_text(
        '{"priority_hypotheses": [], "critical_assets": [], "trust_boundaries": [], "entry_points": []}'
    )
    return tmp_path


@pytest.mark.asyncio
async def test_execute_threat_modeling_run_file_based_fallback(complete_recon_dir: Path) -> None:
    """Pipeline runs with file-based recon_dir and LLM fallback (no LLM)."""
    result = await execute_threat_modeling_run(
        engagement_id="e1",
        run_id="run1",
        job_id="job1",
        recon_dir=complete_recon_dir,
        mcp_tools=[],
    )
    assert result.status == "completed"
    assert result.engagement_id == "e1"
    assert result.run_id == "run1"
    assert result.job_id == "job1"
    assert len(result.artifact_refs) == 25  # 11 base + 11 report + 3 TM2-003/004/005


@pytest.mark.asyncio
async def test_execute_threat_modeling_run_with_mock_llm(complete_recon_dir: Path) -> None:
    """Pipeline uses injected llm_callable when provided."""
    def mock_llm(_prompt: str, context: dict) -> str:
        task = context.get("task", "")
        if task == "critical_assets":
            return '{"assets": [{"id": "ca1", "name": "API", "asset_type": "service", "description": "Main API", "statement_type": "hypothesis", "evidence_refs": []}]}'
        if task == "trust_boundaries":
            return '{"boundaries": [{"id": "tb1", "name": "DMZ", "description": "Zone", "components": [], "statement_type": "hypothesis", "evidence_refs": []}]}'
        if task == "attacker_profiles":
            return '{"profiles": [{"id": "ap1", "name": "Attacker", "capability_level": "script", "description": "Ext", "statement_type": "hypothesis", "evidence_refs": []}]}'
        if task == "entry_points":
            return '{"entry_points": [{"id": "ep1", "name": "API", "entry_type": "api", "host_or_component": None, "description": "API", "statement_type": "hypothesis", "evidence_refs": []}]}'
        if task == "application_flows":
            return '{"flows": [{"id": "f1", "source": "client", "sink": "server", "data_type": "request", "description": "Flow", "statement_type": "hypothesis", "evidence_refs": []}]}'
        if task == "threat_scenarios":
            return '{"scenarios": [{"id": "ts1", "title": "Test", "related_assets": [], "host_component": None, "entry_point": "ep1", "attacker_profile": "ap1", "trust_boundary": "tb1", "description": "Scenario", "likelihood": 0.5, "impact": 0.5, "priority": "medium", "assumptions": [], "recommended_next_manual_checks": [], "statement_type": "hypothesis", "evidence_refs": []}]}'
        if task == "scenario_scoring":
            return '{"scores": [{"scenario_id": "ts1", "likelihood": 0.5, "impact": 0.5, "risk_score": 0.25, "statement_type": "hypothesis", "evidence_refs": []}]}'
        if task == "testing_roadmap":
            return '{"items": [{"scenario_id": "ts1", "title": "Test", "priority": "medium", "recommended_actions": ["Verify"], "statement_type": "hypothesis", "evidence_refs": []}]}'
        if task == "report_summary":
            return '{"executive_summary": "Threat model summary from mock LLM."}'
        return "{}"

    result = await execute_threat_modeling_run(
        engagement_id="e1",
        run_id="run2",
        job_id="job2",
        recon_dir=complete_recon_dir,
        llm_callable=mock_llm,
        mcp_tools=[],
    )
    assert result.status == "completed"
    assert len(result.artifact_refs) == 25  # 11 base + 11 report + 3 TM2-003/004/005
    assert "ai_tm_critical_assets_normalized.json" in result.artifact_refs
    assert "threat_model.md" in result.artifact_refs
    assert "threat_model.json" in result.artifact_refs
    assert "ai_tm_priority_hypotheses.json" in result.artifact_refs
    assert "ai_tm_application_flows.json" in result.artifact_refs
    assert (complete_recon_dir / "ai_tm_critical_assets_normalized.json").exists()


@pytest.mark.asyncio
async def test_execute_threat_modeling_run_blocked_missing_recon() -> None:
    """Pipeline raises when Stage 1 not ready."""
    with pytest.raises(ThreatModelPipelineError, match="Stage 1 not ready"):
        await execute_threat_modeling_run(
            engagement_id="e1",
            run_id="run1",
            job_id="job1",
            recon_dir=Path("/nonexistent/path"),
        )


@pytest.mark.asyncio
async def test_execute_threat_modeling_run_blocked_when_no_recon_no_db() -> None:
    """Pipeline raises when neither recon_dir nor db provided (blocked at dependency check)."""
    with pytest.raises(ThreatModelPipelineError, match="Stage 1 not ready|blocked_missing_recon"):
        await execute_threat_modeling_run(
            engagement_id="e1",
            run_id="run1",
            job_id="job1",
        )
