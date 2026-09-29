"""Part III Phase S — LLM failure diagnostics (R-01, R-02) and health probe.

Regression for the shipped bundle where every finding was ``failed`` with
``remediation: null`` yet the manifest carried ``errors: []`` and a
``report_writer`` alias instead of the real model.
"""

from __future__ import annotations

import json

from src.reports.llm_remediation.bundle import (
    GenerationStatus,
    ValhallaReleaseManifest,
    manifest_consistency_errors,
)
from src.reports.llm_remediation.document import AssessmentCompleteness
from src.reports.llm_remediation.integration import generate_valhalla_llm_release
from src.reports.llm_remediation.runner import (
    LlmFailureKind,
    LlmNotInvokedError,
    RemediationRunner,
    classify_failure,
    format_llm_error,
)

REPORT_META = {
    "report_id": "R1",
    "report_version": "snap-abc",
    "tenant_id": "T1",
    "scan_id": "S1",
    "target": "example.test",
}

_FINDINGS = [
    {"finding_id": "F-1", "title": "t1", "severity": "high", "verification_status": "confirmed"},
    {"finding_id": "F-2", "title": "t2", "severity": "medium", "verification_status": "suspected"},
]


def _remediation(fid: str) -> str:
    return json.dumps(
        {
            "finding_id": fid,
            "analysis_status": "generated_validated",
            "root_cause": {
                "text": "c",
                "established_or_hypothesis": "established",
                "evidence_ids": [],
            },
            "remediation_objective": "obj",
            "permanent_fix_steps": [
                {
                    "step_id": "S1",
                    "component": "web",
                    "action": "act",
                    "rationale": "why",
                    "acceptance_criteria_ids": ["C1"],
                }
            ],
            "priority_rationale": {"text": "p"},
            "acceptance_criteria": [
                {"criterion_id": "C1", "measurable_property": "m", "required_evidence": "e"}
            ],
            "retest_plan": [
                {
                    "test_id": "T1",
                    "criteria_ids": ["C1"],
                    "procedure": "p",
                    "expected_secure_result": "ok",
                }
            ],
            "missing_information": [],
        }
    )


class _ValidEcho:
    def __call__(self, system_prompt: str, user_prompt: str, kind: str) -> str:
        payload = json.loads(user_prompt.split("Входные данные: ", 1)[1])
        fid = payload["identity"]["finding_id"]
        if kind in ("remediation", "probe"):
            return _remediation(fid)
        r = payload["retest"]
        return json.dumps(
            {
                "finding_id": fid,
                "permitted_closure_status": r["permitted_closure_status"],
                "conclusion_text": "c",
                "satisfied_criteria_ids": r["satisfied_criteria_ids"],
                "unsatisfied_criteria_ids": r["unsatisfied_criteria_ids"],
                "untested_criteria_ids": r["untested_criteria_ids"],
                "supporting_retest_ids": r["supporting_retest_ids"],
                "supporting_evidence_ids": r["supporting_evidence_ids"],
                "residual_risk": "r",
                "next_actions": [],
                "blockers": [],
            }
        )


# --------------------------------------------------------------------------- R-01
def test_manifest_errors_populated_on_failure():
    """Broken model → manifest.errors carries the per-finding cause (not empty)."""

    def broken(system_prompt: str, user_prompt: str, kind: str) -> str:
        return "{not json"

    _doc, release = generate_valhalla_llm_release(
        _FINDINGS, report_meta=REPORT_META, llm_callable=broken, provider="cloud_x", model="m-1"
    )
    assert release.manifest.generation_status is not GenerationStatus.READY
    assert release.manifest.errors, "errors must not be empty when analysis failed"
    assert any("llm_schema_invalid" in e for e in release.manifest.errors)
    assert any(e.startswith("finding:F-1") for e in release.manifest.errors)
    assert release.manifest.failure_kinds.get("llm_schema_invalid", 0) >= 1


# --------------------------------------------------------------------------- R-02
def test_failed_completeness_with_empty_errors_blocks_release():
    manifest = ValhallaReleaseManifest(
        report_version="v",
        content_hash="h",
        assessment_completeness=AssessmentCompleteness.FAILED,
        generation_status=GenerationStatus.DRAFT,
        errors=[],
    )
    problems = manifest_consistency_errors(manifest)
    assert any("no recorded errors" in p for p in problems)


def test_provenance_records_real_model_not_alias():
    doc, release = generate_valhalla_llm_release(
        _FINDINGS,
        report_meta=REPORT_META,
        llm_callable=_ValidEcho(),
        provider="cloud_deepseek",
        model="deepseek-chat",
    )
    node = doc.findings[0]
    assert node.remediation is not None
    assert node.remediation.llm_provenance.model == "deepseek-chat"
    assert node.remediation.llm_provenance.provider == "cloud_deepseek"
    assert node.remediation.llm_provenance.model != "report_writer"
    assert release.manifest.llm_model == "deepseek-chat"
    # The deterministic summary must not masquerade as an LLM call.
    if doc.summary is not None:
        assert doc.summary.llm_provenance.validation_status == "app_computed_no_llm_call"
        assert doc.summary.llm_provenance.model != "report_writer"


def test_llm_health_probe_before_per_finding_phase():
    """A failing probe short-circuits: one call total, all findings llm_not_invoked."""
    calls: list[str] = []

    def failing(system_prompt: str, user_prompt: str, kind: str) -> str:
        calls.append(kind)
        raise LlmNotInvokedError("budget ledger unavailable — denying paid cloud call")

    runner = RemediationRunner(failing, provider="cloud_x", model="m-1", sleeper=lambda _s: None)
    result = runner.run(
        _FINDINGS,
        report_meta=REPORT_META,
        closure_inputs={},
        health_probe=True,
    )
    assert calls == ["probe"], "only the probe should be called; per-finding calls skipped"
    assert result.probe_error and "llm_not_invoked" in result.probe_error
    assert all(r.llm_analysis_status == "failed" for r in result.results)
    assert all(r.failure_kind == LlmFailureKind.NOT_INVOKED.value for r in result.results)


def test_classify_and_format_helpers():
    assert classify_failure(["llm_call_failed: stage=remediation"]) == "llm_call_failed"
    assert classify_failure(["invented_evidence_id: x"]) == "llm_validation_rejected"
    assert classify_failure([]) is None
    line = format_llm_error(
        LlmFailureKind.CALL_FAILED, stage="remediation", message="boom", provider="p", model="m"
    )
    assert "llm_call_failed" in line and "provider=p" in line and "model=m" in line
