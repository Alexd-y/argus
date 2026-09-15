"""Shared fixtures/helpers for the Valhalla LLM document/render/bundle tests."""

import json

import pytest
from src.reports.llm_remediation.builder import build_valhalla_llm_document
from src.reports.llm_remediation.closure_status import (
    ClosureComputationInput,
    RetestExecution,
    RetestOutcome,
)
from src.reports.llm_remediation.document import ValhallaLlmDocument
from src.reports.llm_remediation.runner import RemediationRunner

REPORT_META = {
    "report_id": "R1",
    "report_version": "1",
    "tenant_id": "T1",
    "scan_id": "S1",
    "target": "example.test",
}


def remediation_json(finding_id: str, *, evidence_ids=None) -> dict:
    return {
        "finding_id": finding_id,
        "analysis_status": "generated_validated",
        "root_cause": {
            "text": "root cause",
            "established_or_hypothesis": "established",
            "evidence_ids": evidence_ids or [],
        },
        "remediation_objective": "objective",
        "permanent_fix_steps": [
            {
                "step_id": "S1",
                "component": "web",
                "action": "stop serving file",
                "rationale": "removes exposure",
                "acceptance_criteria_ids": ["C1"],
            }
        ],
        "priority_rationale": {"text": "high impact"},
        "acceptance_criteria": [
            {
                "criterion_id": "C1",
                "measurable_property": "file not served",
                "required_evidence": "http 404",
            }
        ],
        "retest_plan": [
            {
                "test_id": "T1",
                "criteria_ids": ["C1"],
                "procedure": "GET /.env",
                "expected_secure_result": "404/403",
            }
        ],
        "missing_information": [],
    }


def closure_json(finding_id: str, permitted: dict) -> dict:
    return {
        "finding_id": finding_id,
        "permitted_closure_status": permitted["permitted_closure_status"],
        "conclusion_text": "conclusion",
        "satisfied_criteria_ids": permitted["satisfied_criteria_ids"],
        "unsatisfied_criteria_ids": permitted["unsatisfied_criteria_ids"],
        "untested_criteria_ids": permitted["untested_criteria_ids"],
        "supporting_retest_ids": permitted["supporting_retest_ids"],
        "supporting_evidence_ids": permitted["supporting_evidence_ids"],
        "residual_risk": "documented",
        "next_actions": [],
        "blockers": [],
    }


class ContextEchoFake:
    """Mock LLM that echoes the app-computed permitted status + sets from context."""

    def __call__(self, system_prompt: str, user_prompt: str, kind: str) -> str:
        payload = json.loads(user_prompt.split("Входные данные: ", 1)[1])
        fid = payload["identity"]["finding_id"]
        if kind == "remediation":
            allowed = payload["evidence"]["allowed_evidence_ids"]
            return json.dumps(remediation_json(fid, evidence_ids=allowed))
        return json.dumps(closure_json(fid, payload["retest"]))


def build_complete_document() -> ValhallaLlmDocument:
    """A 2-finding document: F-1 fixed_verified, F-2 not_retested; all validated."""

    findings = [
        {"finding_id": "F-1", "title": "Exposed .env", "description": "leak", "severity": "high"},
        {"finding_id": "F-2", "title": "Missing CSP", "description": "no csp", "severity": "low"},
    ]
    runner = RemediationRunner(
        ContextEchoFake(), provider="mock", model="mock-1", sleeper=lambda _s: None
    )
    run_result = runner.run(
        findings,
        report_meta=REPORT_META,
        closure_inputs={
            "F-1": ClosureComputationInput(
                finding_id="F-1",
                acceptance_criteria_ids=("C1",),
                retests=(RetestExecution("T1", RetestOutcome.PASS_SECURE, ("C1",), ("E1",)),),
            ),
            "F-2": ClosureComputationInput(finding_id="F-2", acceptance_criteria_ids=("C1",)),
        },
        allowed_evidence_ids={"F-1": ["E1"]},
    )
    return build_valhalla_llm_document(
        run_result,
        report_meta=REPORT_META,
        finding_meta={
            "F-1": {
                "title": "Exposed .env",
                "severity": "high",
                "verification_status": "confirmed",
            },
            "F-2": {"title": "Missing CSP", "severity": "low", "verification_status": "suspected"},
        },
        canonical_snapshot_hash="snap-hash-1234",
    )


@pytest.fixture
def complete_document() -> ValhallaLlmDocument:
    return build_complete_document()


@pytest.fixture
def document_factory():
    """Return the builder so a test can create independent documents."""
    return build_complete_document


@pytest.fixture
def report_meta() -> dict:
    return dict(REPORT_META)
