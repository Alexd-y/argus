"""Orchestration runner with a mock LLM (prompt acceptance checks L01–L28 subset)."""

import json
from collections import Counter

from src.reports.llm_remediation.closure_status import (
    ClosureComputationInput,
    RetestExecution,
    RetestOutcome,
)
from src.reports.llm_remediation.runner import RemediationRunner

REPORT_META = {"report_version": "1", "report_id": "R1", "scan_id": "S1", "tenant_id": "T1"}


def _no_sleep(_seconds: float) -> None:
    return None


def remediation_json(finding_id: str, *, evidence_ids=None, ref_ids=None) -> dict:
    return {
        "finding_id": finding_id,
        "analysis_status": "generated_validated",
        "root_cause": {
            "text": "root cause",
            "established_or_hypothesis": "established",
            "evidence_ids": evidence_ids or [],
        },
        "remediation_objective": "objective",
        "immediate_containment": [],
        "permanent_fix_steps": [
            {
                "step_id": "S1",
                "component": "web",
                "action": "stop serving file",
                "rationale": "removes exposure",
                "acceptance_criteria_ids": ["C1"],
                "source_reference_ids": ref_ids or [],
            }
        ],
        "preventive_measures": [],
        "priority_rationale": {"text": "high impact", "fact_refs": [], "assumptions": []},
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
        "assumptions": [],
    }


def closure_json(
    finding_id: str,
    status: str,
    *,
    satisfied=None,
    unsatisfied=None,
    untested=None,
    retests=None,
    evidence=None,
) -> dict:
    return {
        "finding_id": finding_id,
        "permitted_closure_status": status,
        "conclusion_text": "conclusion",
        "satisfied_criteria_ids": satisfied or [],
        "unsatisfied_criteria_ids": unsatisfied or [],
        "untested_criteria_ids": untested or [],
        "supporting_retest_ids": retests or [],
        "supporting_evidence_ids": evidence or [],
        "residual_risk": "documented",
        "next_actions": [],
        "blockers": [],
    }


class FakeLLM:
    """Configurable mock: per-kind response queues; strings returned verbatim."""

    def __init__(self, *, remediation=None, closure=None):
        self._responses = {"remediation": remediation or [], "closure": closure or []}
        self.counts: Counter[str] = Counter()

    def __call__(self, system_prompt: str, user_prompt: str, kind: str) -> str:
        idx = self.counts[kind]
        self.counts[kind] += 1
        queue = self._responses.get(kind) or []
        item = queue[min(idx, len(queue) - 1)] if queue else "{}"
        if isinstance(item, str):
            return item
        return json.dumps(item)


def _runner(fake: FakeLLM, **kw) -> RemediationRunner:
    return RemediationRunner(fake, provider="mock", model="mock-1", sleeper=_no_sleep, **kw)


def test_all_findings_processed_including_last():
    """L01/L28: every finding gets an analysis + closure; last item included."""
    findings = [{"finding_id": f"F-{i}", "title": f"t{i}", "description": "d"} for i in range(3)]

    # The mock must echo each finding's own id; derive it from the context
    # embedded in the user prompt so every finding gets its own analysis.
    class PerFindingFake(FakeLLM):
        def __call__(self, system_prompt, user_prompt, kind):
            self.counts[kind] += 1
            payload = json.loads(user_prompt.split("Входные данные: ", 1)[1])
            fid = payload["identity"]["finding_id"]
            if kind == "remediation":
                return json.dumps(remediation_json(fid))
            return json.dumps(closure_json(fid, "not_retested", untested=["C1"]))

    fake = PerFindingFake()
    runner = _runner(fake)
    result = runner.run(
        findings,
        report_meta=REPORT_META,
        closure_inputs={
            f"F-{i}": ClosureComputationInput(finding_id=f"F-{i}", acceptance_criteria_ids=("C1",))
            for i in range(3)
        },
    )
    assert len(result.results) == 3
    assert {r.finding_id for r in result.results} == {"F-0", "F-1", "F-2"}
    assert all(r.llm_analysis_status == "generated_validated" for r in result.results)
    assert result.summary is not None
    assert (
        result.summary.exact_counts_by_verification_and_remediation_status["generated_validated"]
        == 3
    )


def test_no_post_fix_evidence_not_fixed_verified():
    """L02: without a retest the closure may not claim fixed_verified."""
    finding = {"finding_id": "F-1", "title": "t", "description": "d"}
    fake = FakeLLM(
        remediation=[remediation_json("F-1")],
        closure=[closure_json("F-1", "not_retested", untested=["C1"])],
    )
    runner = _runner(fake)
    res = runner.analyze_finding(
        finding,
        report_meta=REPORT_META,
        closure_input=ClosureComputationInput(finding_id="F-1", acceptance_criteria_ids=("C1",)),
    )
    assert res.llm_analysis_status == "generated_validated"
    assert res.closure is not None
    assert res.closure.permitted_closure_status.value == "not_retested"
    assert res.permitted_status.value == "not_retested"


def test_all_criteria_pass_fixed_verified():
    """L05: all criteria satisfied by evidence-backed retest → fixed_verified."""
    finding = {"finding_id": "F-1", "title": "t", "description": "d"}
    fake = FakeLLM(
        remediation=[remediation_json("F-1", evidence_ids=["E1"])],
        closure=[
            closure_json("F-1", "fixed_verified", satisfied=["C1"], retests=["T1"], evidence=["E1"])
        ],
    )
    runner = _runner(fake)
    res = runner.analyze_finding(
        finding,
        report_meta=REPORT_META,
        closure_input=ClosureComputationInput(
            finding_id="F-1",
            acceptance_criteria_ids=("C1",),
            retests=(RetestExecution("T1", RetestOutcome.PASS_SECURE, ("C1",), ("E1",)),),
        ),
        allowed_evidence_ids=["E1"],
    )
    assert res.permitted_status.value == "fixed_verified"
    assert res.closure.permitted_closure_status.value == "fixed_verified"
    assert res.llm_analysis_status == "generated_validated"


def test_invented_evidence_id_routes_to_needs_review():
    """L07: a hallucinated evidence id is rejected, not published."""
    finding = {"finding_id": "F-1", "title": "t", "description": "d"}
    fake = FakeLLM(
        remediation=[remediation_json("F-1")],
        closure=[closure_json("F-1", "not_retested", untested=["C1"], evidence=["E-999"])],
    )
    runner = _runner(fake)
    res = runner.analyze_finding(
        finding,
        report_meta=REPORT_META,
        closure_input=ClosureComputationInput(finding_id="F-1", acceptance_criteria_ids=("C1",)),
        allowed_evidence_ids=["E1"],
    )
    assert res.llm_analysis_status == "needs_review"
    assert any("invented_evidence_id" in e for e in res.errors)


def test_model_cannot_strengthen_status_clamped():
    """L08: model claiming fixed_verified when not retested is clamped down."""
    finding = {"finding_id": "F-1", "title": "t", "description": "d"}
    fake = FakeLLM(
        remediation=[remediation_json("F-1")],
        closure=[
            closure_json("F-1", "fixed_verified", satisfied=["C1"], retests=["T1"], evidence=["E1"])
        ],
    )
    runner = _runner(fake)
    res = runner.analyze_finding(
        finding,
        report_meta=REPORT_META,
        closure_input=ClosureComputationInput(finding_id="F-1", acceptance_criteria_ids=("C1",)),
    )
    assert res.closure is not None
    assert res.closure.permitted_closure_status.value == "not_retested"
    assert res.llm_analysis_status == "needs_review"
    assert any("clamped_status" in e for e in res.errors)


def test_invalid_json_exhausts_repair_then_failed():
    """L09: unrecoverable invalid JSON → failed, never a false final."""
    finding = {"finding_id": "F-1", "title": "t", "description": "d"}
    fake = FakeLLM(
        remediation=[remediation_json("F-1")],
        closure=["{not valid json", "still {not json"],
    )
    runner = _runner(fake, max_repair_attempts=1)
    res = runner.analyze_finding(
        finding,
        report_meta=REPORT_META,
        closure_input=ClosureComputationInput(finding_id="F-1", acceptance_criteria_ids=("C1",)),
    )
    assert res.llm_analysis_status == "failed"
    assert res.closure is None


def test_cache_reuse_avoids_second_llm_call():
    """L10/L23: identical inputs reuse the validated output; no re-analysis."""
    finding = {"finding_id": "F-1", "title": "t", "description": "d"}
    fake = FakeLLM(
        remediation=[remediation_json("F-1")],
        closure=[closure_json("F-1", "not_retested", untested=["C1"])],
    )
    runner = _runner(fake)
    ci = ClosureComputationInput(finding_id="F-1", acceptance_criteria_ids=("C1",))
    first = runner.analyze_finding(finding, report_meta=REPORT_META, closure_input=ci)
    calls_after_first = dict(fake.counts)
    second = runner.analyze_finding(finding, report_meta=REPORT_META, closure_input=ci)

    assert first.from_cache is False
    assert second.from_cache is True
    assert dict(fake.counts) == calls_after_first  # no additional LLM calls
    assert second.llm_analysis_status == "generated_validated"
