"""Phase 9 — Cairn ↔ pipeline seam + Fact→Finding evidence gate (§11.3/§11.5)."""

from __future__ import annotations

from src.orchestration.cairn_phase import (
    cairn_engine_mode,
    cairn_inner_loop_enabled,
    cap_evidence_tier,
    fact_to_finding,
    promote_facts_to_findings,
)
from src.orchestration.evidence_tier import EvidenceTier

# --- flags -------------------------------------------------------------------


def test_engine_mode_defaults_to_pipeline() -> None:
    assert cairn_engine_mode(None) == "pipeline"
    assert cairn_engine_mode({}) == "pipeline"
    assert cairn_engine_mode({"engine": "cairn"}) == "cairn"
    assert cairn_engine_mode({"engine": "CAIRN"}) == "cairn"


def test_inner_loop_off_by_default() -> None:
    assert cairn_inner_loop_enabled({}, "vuln_analysis") is False
    assert cairn_inner_loop_enabled({"cairn_enabled": True}, "vuln_analysis") is True
    assert cairn_inner_loop_enabled({"cairn_enabled": True}, "recon") is False
    assert (
        cairn_inner_loop_enabled({"cairn_enabled": True, "cairn_phases": ["recon"]}, "recon")
        is True
    )


# --- evidence tier cap (the critical rule) -----------------------------------


def test_fact_without_evidence_capped_at_suspected() -> None:
    fact = {
        "ref": "f001",
        "description": "looks exploitable",
        "evidence_tier": int(EvidenceTier.EXPLOITED),
    }
    assert cap_evidence_tier(fact) == EvidenceTier.SUSPECTED


def test_fact_with_artifact_keeps_higher_tier() -> None:
    fact = {
        "ref": "f001",
        "description": "RCE proven",
        "evidence_tier": int(EvidenceTier.EXPLOITED),
        "artifact_object_key": "s3://k/shell.txt",
    }
    assert cap_evidence_tier(fact) == EvidenceTier.EXPLOITED


def test_fact_with_evidence_refs_keeps_confirmed() -> None:
    fact = {
        "ref": "f002",
        "description": "reflected xss",
        "evidence_tier": int(EvidenceTier.CONFIRMED),
        "evidence_refs": ["ev-1"],
    }
    assert cap_evidence_tier(fact) == EvidenceTier.CONFIRMED


def test_missing_tier_defaults_to_suspected() -> None:
    assert cap_evidence_tier({"ref": "f003", "description": "x"}) == EvidenceTier.SUSPECTED


# --- fact -> finding mapping -------------------------------------------------


def test_fact_to_finding_carries_provenance() -> None:
    fact = {
        "ref": "f001",
        "description": "SQLi at /login",
        "evidence_refs": ["ev1"],
        "evidence_tier": 3,
    }
    finding = fact_to_finding(fact, project_id="proj-1", intent_ref="i002")
    assert finding["provenance"] == {
        "cairn_project_id": "proj-1",
        "cairn_fact_ref": "f001",
        "cairn_intent_ref": "i002",
    }
    assert finding["title"] == "SQLi at /login"
    assert finding["source"] == "cairn"


def test_promote_excludes_origin_and_goal() -> None:
    facts = [
        {"ref": "origin", "description": "http://target"},
        {"ref": "goal", "description": "get RCE"},
        {
            "ref": "f001",
            "description": "Tomcat 9 with CVE-2026-1234 confirmed",
            "evidence_refs": ["ev1"],
            "evidence_tier": 3,
        },
    ]
    findings = promote_facts_to_findings(facts, project_id="p1")
    refs = {f["provenance"]["cairn_fact_ref"] for f in findings}
    assert refs == {"f001"}


def test_promote_caps_no_evidence_fact() -> None:
    facts = [
        {
            "ref": "f001",
            "description": "This looks like a serious remote code execution issue",
            "evidence_tier": int(EvidenceTier.EXPLOITED),
        }
    ]
    findings = promote_facts_to_findings(facts, project_id="p1")
    assert findings, "a described fact should survive the gate as WEAK"
    assert findings[0]["evidence_tier"] <= int(EvidenceTier.SUSPECTED)
