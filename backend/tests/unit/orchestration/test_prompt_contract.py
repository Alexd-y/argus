"""Block 5 — anti-hallucination evidence contract injected into phase prompts."""

from __future__ import annotations

from src.orchestration.prompt_registry import (
    ANTI_HALLUCINATION_CONTRACT,
    _apply_evidence_contract,
)


def test_base_contract_present_for_all_phases():
    for phase in ("recon", "threat_modeling", "vuln_analysis", "exploitation",
                  "post_exploitation", "reporting"):
        out = _apply_evidence_contract(phase, "SYSTEM")
        assert out.startswith("SYSTEM")
        assert "STRICT EVIDENCE CONTRACT" in out
        assert "do NOT create findings" in out


def test_vuln_analysis_requires_hypotheses_clause():
    out = _apply_evidence_contract("vuln_analysis", "SYS")
    assert "hypotheses" in out
    assert "evidence_quality >= weak" in out


def test_exploitation_requires_poc_or_unconfirmed():
    out = _apply_evidence_contract("exploitation", "SYS")
    assert "unconfirmed" in out
    assert "NEVER report 'exploited' without" in out


def test_post_exploitation_forbids_speculation():
    out = _apply_evidence_contract("post_exploitation", "SYS")
    assert "empty arrays" in out
    assert "confirmed exploit artifact" in out


def test_reporting_no_access_without_artifact():
    out = _apply_evidence_contract("reporting", "SYS")
    assert "no claim of access" in out.lower()


def test_phase_without_specific_clause_gets_base_only():
    out = _apply_evidence_contract("recon", "SYS")
    assert out == "SYS" + ANTI_HALLUCINATION_CONTRACT
