"""Unit tests for Confirmation Policy Module (VA3UP-006)."""

from __future__ import annotations

import pytest

from app.schemas.vulnerability_analysis.scenario_mapping import (
    FindingAssetLink,
    FindingScenarioLink,
    FindingToScenarioMap,
)
from app.schemas.vulnerability_analysis.schemas import FindingStatus
from src.recon.vulnerability_analysis.confirmation_policy import (
    evaluate_confirmation_policy,
    get_blocking_reasons_for_next_phase,
)
from src.recon.vulnerability_analysis.contradiction_analysis import analyze_contradictions
from src.recon.vulnerability_analysis.evidence_sufficiency import evaluate_evidence_sufficiency


def _make_sufficient_finding(finding_id: str = "f1") -> dict:
    """Create AI result with sufficient evidence for a finding."""
    return {
        "authorization_analysis": {
            "checks": [
                {
                    "target_id": finding_id,
                    "description": "Test check",
                    "evidence_refs": ["artifact:foo", "recon:bar"],
                    "confidence": 0.8,
                    "statement_type": "evidence",
                },
            ],
        },
    }


def test_evaluate_empty_findings() -> None:
    """No decisions when no findings in sufficiency/contradiction."""
    suff = evaluate_evidence_sufficiency({}, "run1", "job1")
    cont = analyze_contradictions({}, "run1", "job1")
    result = evaluate_confirmation_policy(suff, cont, "run1", "job1")
    assert result.run_id == "run1"
    assert result.job_id == "job1"
    assert len(result.decisions) == 0
    assert result.summary.get("total", 0) == 0


def test_evaluate_confirmed_without_linkage_invalid_for_gate() -> None:
    """Confirmed finding without asset/scenario linkage is invalid for gate."""
    ai = _make_sufficient_finding("auth-1")
    suff = evaluate_evidence_sufficiency(ai, "r1", "j1")
    cont = analyze_contradictions(ai, "r1", "j1")
    result = evaluate_confirmation_policy(suff, cont, "r1", "j1")
    assert len(result.decisions) == 1
    d = result.decisions[0]
    assert d.recommended_status == FindingStatus.CONFIRMED
    assert d.is_valid_for_gate is False
    assert "confirmed_without_asset_or_scenario_linkage" in d.block_reasons


def test_evaluate_confirmed_with_linkage_valid_for_gate() -> None:
    """Confirmed finding with asset/scenario linkage is valid for gate."""
    ai = _make_sufficient_finding("auth-1")
    suff = evaluate_evidence_sufficiency(ai, "r1", "j1")
    cont = analyze_contradictions(ai, "r1", "j1")
    scenario_map = FindingToScenarioMap(
        scenario_links=[
            FindingScenarioLink(
                finding_id="auth-1",
                scenario_id="s1",
                link_type="check",
                rationale="test",
                evidence_refs=[],
            )
        ],
        boundary_links=[],
        asset_links=[
            FindingAssetLink(
                finding_id="auth-1",
                asset_id="a1",
                rationale="test",
                evidence_refs=[],
            )
        ],
    )
    result = evaluate_confirmation_policy(
        suff, cont, "r1", "j1", scenario_map=scenario_map
    )
    d = result.decisions[0]
    assert d.recommended_status == FindingStatus.CONFIRMED
    assert d.is_valid_for_gate is True
    assert "confirmed_without_asset_or_scenario_linkage" not in d.block_reasons


def test_get_blocking_reasons_no_confirmed() -> None:
    """Blocking reasons when no confirmed findings."""
    ai = {
        "authorization_analysis": {
            "checks": [
                {
                    "target_id": "h1",
                    "evidence_refs": [],
                    "confidence": 0.4,
                    "statement_type": "hypothesis",
                },
            ],
        },
    }
    suff = evaluate_evidence_sufficiency(ai, "r1", "j1")
    cont = analyze_contradictions(ai, "r1", "j1")
    result = evaluate_confirmation_policy(suff, cont, "r1", "j1")
    reasons = get_blocking_reasons_for_next_phase(result)
    assert "blocked_no_confirmed_findings" in reasons


def test_get_blocking_reasons_confirmed_invalid_for_gate() -> None:
    """Blocking reasons when confirmed but invalid for gate."""
    ai = _make_sufficient_finding("auth-1")
    suff = evaluate_evidence_sufficiency(ai, "r1", "j1")
    cont = analyze_contradictions(ai, "r1", "j1")
    result = evaluate_confirmation_policy(suff, cont, "r1", "j1")
    reasons = get_blocking_reasons_for_next_phase(result)
    assert "blocked_confirmed_findings_invalid_for_gate" in reasons


def test_get_blocking_reasons_ready_when_valid_confirmed() -> None:
    """No blocking reasons when at least one confirmed finding valid for gate."""
    ai = _make_sufficient_finding("auth-1")
    suff = evaluate_evidence_sufficiency(ai, "r1", "j1")
    cont = analyze_contradictions(ai, "r1", "j1")
    scenario_map = FindingToScenarioMap(
        scenario_links=[
            FindingScenarioLink(
                finding_id="auth-1",
                scenario_id="s1",
                link_type="check",
                rationale="test",
                evidence_refs=[],
            )
        ],
        boundary_links=[],
        asset_links=[],
    )
    result = evaluate_confirmation_policy(
        suff, cont, "r1", "j1", scenario_map=scenario_map
    )
    reasons = get_blocking_reasons_for_next_phase(result)
    assert "blocked_no_confirmed_findings" not in reasons
    assert "blocked_confirmed_findings_invalid_for_gate" not in reasons


def test_allowed_transitions_imported() -> None:
    """Verify ALLOWED_TRANSITIONS is defined and used."""
    from src.recon.vulnerability_analysis.confirmation_policy import ALLOWED_TRANSITIONS

    assert FindingStatus.HYPOTHESIS in ALLOWED_TRANSITIONS
    assert FindingStatus.CONFIRMED in ALLOWED_TRANSITIONS
    assert FindingStatus.REJECTED in ALLOWED_TRANSITIONS
