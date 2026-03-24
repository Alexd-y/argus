"""OWASP-006: VA active-scan AI tasks — prompts, registry order, Pydantic validation, partial runner."""

from __future__ import annotations

import pytest

from app.prompts.vulnerability_analysis_prompts import VA_PROMPT_GETTERS, get_vulnerability_analysis_prompt
from app.schemas.ai.common import VulnerabilityAnalysisAiTask, build_va_task_metadata
from app.schemas.threat_modeling.schemas import EntryPoint
from app.schemas.vulnerability_analysis.ai_tasks import (
    ActiveScanPlanningOutput,
    NucleiAnalysisOutput,
    SqliAnalysisOutput,
    XssAnalysisOutput,
)
from app.schemas.vulnerability_analysis.schemas import VulnerabilityAnalysisInputBundle
from src.recon.vulnerability_analysis.ai_task_registry import (
    VA_ACTIVE_SCAN_AI_TASKS,
    VA_AI_TASKS,
    validate_va_ai_payload,
)
from src.recon.vulnerability_analysis.pipeline import run_active_scan_ai_tasks


def _minimal_bundle() -> VulnerabilityAnalysisInputBundle:
    return VulnerabilityAnalysisInputBundle(
        engagement_id="e1",
        entry_points=[
            EntryPoint(
                id="ep1",
                name="Home",
                entry_type="url",
                host_or_component="https://example.com/",
            ),
        ],
        intel_findings=[
            {"type": "xss", "url": "https://example.com/q", "parameter": "q", "description": "reflected"},
            {"type": "sqli", "url": "https://example.com/api", "parameter": "id"},
        ],
    )


@pytest.mark.parametrize(
    "task",
    [
        VulnerabilityAnalysisAiTask.ACTIVE_SCAN_PLANNING,
        VulnerabilityAnalysisAiTask.XSS_ANALYSIS,
        VulnerabilityAnalysisAiTask.SQLI_ANALYSIS,
        VulnerabilityAnalysisAiTask.NUCLEI_ANALYSIS,
    ],
)
def test_owasp006_prompt_registered(task: VulnerabilityAnalysisAiTask) -> None:
    name = task.value
    assert name in VA_PROMPT_GETTERS
    text = get_vulnerability_analysis_prompt(name)
    assert len(text) > 80
    assert "evidence" in text.lower()


def test_va_ai_tasks_active_scan_prefix_order() -> None:
    assert VA_AI_TASKS[: len(VA_ACTIVE_SCAN_AI_TASKS)] == VA_ACTIVE_SCAN_AI_TASKS
    assert VulnerabilityAnalysisAiTask.VALIDATION_TARGET_PLANNING.value == VA_AI_TASKS[len(VA_ACTIVE_SCAN_AI_TASKS)]


def test_validate_active_scan_planning_payload() -> None:
    bundle = _minimal_bundle()
    task = VulnerabilityAnalysisAiTask.ACTIVE_SCAN_PLANNING
    meta = build_va_task_metadata(task, "r1", "j1", "e1")
    inp = {"meta": meta.model_dump(mode="json"), "bundle": bundle.model_dump(mode="json")}
    out = {
        "plans": [
            {
                "target_url": "https://example.com/",
                "rationale": "Entry surface",
                "target_id": "ep1",
                "statement_type": "hypothesis",
                "evidence_refs": [],
                "confidence": 0.5,
            }
        ]
    }
    v = validate_va_ai_payload(task.value, inp, out)
    assert v["input"]["is_valid"], v
    assert v["output"]["is_valid"], v
    ActiveScanPlanningOutput.model_validate(out)


def test_va_owasp006_validate_nuclei_analysis_payload() -> None:
    bundle = _minimal_bundle()
    bundle.intel_findings = [
        *list(bundle.intel_findings or []),
        {
            "finding_type": "vulnerability",
            "value": "nuclei:probe-x:https://example.com/x",
            "data": {
                "type": "NUCLEI",
                "template_id": "probe-x",
                "name": "Probe",
                "matched_at": "https://example.com/x",
                "severity": "medium",
                "matcher_name": "status",
            },
            "source_tool": "nuclei",
            "confidence": 0.72,
        },
    ]
    task = VulnerabilityAnalysisAiTask.NUCLEI_ANALYSIS
    meta = build_va_task_metadata(task, "r1", "j1", "e1")
    inp = {"meta": meta.model_dump(mode="json"), "bundle": bundle.model_dump(mode="json")}
    out = {
        "findings": [
            {
                "description": "Nuclei medium-severity hit (probe-x) on /x; validate matcher status.",
                "statement_type": "evidence",
                "evidence_refs": ["intel_findings:item_2"],
                "confidence": 0.75,
                "template_id": "probe-x",
                "matched_at": "https://example.com/x",
                "severity": "medium",
                "template_name": "Probe",
                "matcher_name": "status",
            }
        ]
    }
    v = validate_va_ai_payload(task.value, inp, out)
    assert v["input"]["is_valid"], v
    assert v["output"]["is_valid"], v
    NucleiAnalysisOutput.model_validate(out)


def test_validate_xss_and_sqli_outputs() -> None:
    bundle = _minimal_bundle()
    cases: list[tuple[VulnerabilityAnalysisAiTask, type, dict]] = [
        (
            VulnerabilityAnalysisAiTask.XSS_ANALYSIS,
            XssAnalysisOutput,
            {
                "findings": [
                    {
                        "description": "XSS on q",
                        "statement_type": "evidence",
                        "evidence_refs": ["intel_findings:item_0"],
                        "confidence": 0.8,
                    }
                ]
            },
        ),
        (
            VulnerabilityAnalysisAiTask.SQLI_ANALYSIS,
            SqliAnalysisOutput,
            {
                "findings": [
                    {
                        "description": "SQLi on id",
                        "statement_type": "hypothesis",
                        "evidence_refs": [],
                        "confidence": 0.4,
                    }
                ]
            },
        ),
    ]
    for task, out_model, body in cases:
        meta = build_va_task_metadata(task, "r1", "j1", "e1")
        inp = {"meta": meta.model_dump(mode="json"), "bundle": bundle.model_dump(mode="json")}
        v = validate_va_ai_payload(task.value, inp, body)
        assert v["input"]["is_valid"], v
        assert v["output"]["is_valid"], v
        out_model.model_validate(body)


def test_non_hypothesis_requires_evidence_refs() -> None:
    task = VulnerabilityAnalysisAiTask.XSS_ANALYSIS
    meta = build_va_task_metadata(task, "r1", "j1", "e1")
    bundle = _minimal_bundle()
    inp = {"meta": meta.model_dump(mode="json"), "bundle": bundle.model_dump(mode="json")}
    bad = {
        "findings": [
            {
                "description": "x",
                "statement_type": "evidence",
                "evidence_refs": [],
                "confidence": 1.0,
            }
        ]
    }
    v = validate_va_ai_payload(task.value, inp, bad)
    assert not v["output"]["is_valid"]


def test_run_active_scan_ai_tasks_updates_prior() -> None:
    bundle = _minimal_bundle()
    prior: dict[str, dict] = {}
    out = run_active_scan_ai_tasks(
        bundle,
        prior,
        "r1",
        "j1",
        "e1",
        call_llm=None,
        use_llm_fallback=True,
    )
    assert set(out.keys()) == set(VA_ACTIVE_SCAN_AI_TASKS)
    for k in VA_ACTIVE_SCAN_AI_TASKS:
        assert k in prior
    assert "plans" in prior["active_scan_planning"]
    assert "findings" in prior["xss_analysis"]
    assert "findings" in prior["sqli_analysis"]
    assert "findings" in prior["nuclei_analysis"]
