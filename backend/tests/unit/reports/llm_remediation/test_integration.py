"""VH-LLM end-to-end call point: findings -> analysis -> release."""

import json

from src.reports.llm_remediation.bundle import GenerationStatus
from src.reports.llm_remediation.integration import (
    finding_to_closure_input,
    generate_valhalla_llm_release,
)

REPORT_META = {
    "report_id": "R1",
    "report_version": "snap-abc",
    "tenant_id": "T1",
    "scan_id": "S1",
    "target": "example.test",
}


def _remediation(fid: str) -> dict:
    return {
        "finding_id": fid,
        "analysis_status": "generated_validated",
        "root_cause": {"text": "c", "established_or_hypothesis": "established", "evidence_ids": []},
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


class EchoFake:
    def __call__(self, system_prompt: str, user_prompt: str, kind: str) -> str:
        payload = json.loads(user_prompt.split("Входные данные: ", 1)[1])
        fid = payload["identity"]["finding_id"]
        if kind == "remediation":
            return json.dumps(_remediation(fid))
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


def test_closure_input_mapping():
    fp = finding_to_closure_input({"finding_id": "F", "validation_status": "false_positive"})
    assert fp.is_false_positive
    ra = finding_to_closure_input({"finding_id": "F", "verification_status": "accepted_risk"})
    assert ra.risk_accepted
    plain = finding_to_closure_input({"finding_id": "F", "validation_status": "confirmed"})
    assert not plain.is_false_positive and not plain.risk_accepted


def test_generate_release_ready_when_all_validated():
    findings = [
        {
            "finding_id": "F-1",
            "title": "t1",
            "severity": "high",
            "verification_status": "confirmed",
        },
        {"finding_id": "F-2", "title": "t2", "severity": "low", "verification_status": "suspected"},
    ]
    doc, release = generate_valhalla_llm_release(
        findings,
        report_meta=REPORT_META,
        llm_callable=EchoFake(),
        formats=["json", "md", "xml", "html"],
        canonical_snapshot_hash="snap-abc",
    )
    assert [n.finding_id for n in doc.findings] == ["F-1", "F-2"]
    assert release.manifest.generation_status is GenerationStatus.READY
    assert release.is_ready
    assert set(release.artifacts) == {"json", "md", "xml", "html"}
    # No retest data -> honest not_retested, never fabricated fixed_verified.
    assert all(n.closure.permitted_closure_status.value == "not_retested" for n in doc.findings)


def test_generate_release_draft_when_llm_fails():
    def broken_llm(system_prompt: str, user_prompt: str, kind: str) -> str:
        return "{not json"

    findings = [{"finding_id": "F-1", "title": "t", "verification_status": "confirmed"}]
    doc, release = generate_valhalla_llm_release(
        findings,
        report_meta=REPORT_META,
        llm_callable=broken_llm,
        formats=["json", "md", "xml", "html"],
    )
    # Honest failure: not ready, artifacts still produced as a draft/failed set.
    assert release.manifest.generation_status is not GenerationStatus.READY
    assert doc.assessment_completeness.value in {"failed", "incomplete"}
