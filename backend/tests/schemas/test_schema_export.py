import json
from pathlib import Path
from typing import Any

import pytest
from app.schemas.ai.common import ReconAiTask, ReportSectionId, build_task_metadata
from app.schemas.ai.schema_export import (
    RECON_AI_TASKS,
    export_recon_ai_schemas,
    get_recon_ai_task_definitions,
    to_report_notes,
    validate_recon_ai_payload,
)
from src.recon.reporting.stage1_contract import STAGE1_BASELINE_ARTIFACTS

EXAMPLES_AI_OUTPUTS_DIR = Path(__file__).resolve().parents[2] / "examples" / "ai_outputs"
NON_HYPOTHESIS_TASKS = tuple(
    task_name for task_name in RECON_AI_TASKS if task_name != ReconAiTask.ANOMALY_INTERPRETATION.value
)
TASK_EXPECTED_STATEMENT_TYPE: dict[str, str] = {
    ReconAiTask.JS_FINDINGS_ANALYSIS.value: "observation",
    ReconAiTask.PARAMETER_INPUT_ANALYSIS.value: "observation",
    ReconAiTask.API_SURFACE_INFERENCE.value: "inference",
    ReconAiTask.HEADERS_TLS_SUMMARY.value: "observation",
    ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION.value: "inference",
    ReconAiTask.ANOMALY_INTERPRETATION.value: "hypothesis",
    ReconAiTask.STAGE2_PREPARATION_SUMMARY.value: "hypothesis",
    ReconAiTask.STAGE3_PREPARATION_SUMMARY.value: "hypothesis",
}
TASK_EXPECTED_SECTION: dict[str, str] = {
    ReconAiTask.JS_FINDINGS_ANALYSIS.value: ReportSectionId.JS_FRONTEND_ANALYSIS.value,
    ReconAiTask.PARAMETER_INPUT_ANALYSIS.value: ReportSectionId.PARAMS_INPUT_SURFACES.value,
    ReconAiTask.API_SURFACE_INFERENCE.value: ReportSectionId.API_SURFACE_MAPPING.value,
    ReconAiTask.HEADERS_TLS_SUMMARY.value: ReportSectionId.HEADERS_TLS.value,
    ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION.value: ReportSectionId.CONTENT_ROUTING.value,
    ReconAiTask.ANOMALY_INTERPRETATION.value: ReportSectionId.ANOMALY_VALIDATION.value,
    ReconAiTask.STAGE2_PREPARATION_SUMMARY.value: ReportSectionId.STAGE2_PREP.value,
    ReconAiTask.STAGE3_PREPARATION_SUMMARY.value: ReportSectionId.STAGE3_READINESS.value,
}


def _build_valid_input_payload(task_name: str) -> dict[str, Any]:
    meta = build_task_metadata(
        task=ReconAiTask(task_name),
        run_id="run-1",
        job_id="job-1",
    ).model_dump(mode="json")

    if task_name == ReconAiTask.JS_FINDINGS_ANALYSIS.value:
        return {
            "meta": meta,
            "script_findings": [
                {
                    "category": "api_ref",
                    "value": "/api/v1/users",
                    "evidence_refs": ["js:app.js:/api/v1/users"],
                }
            ],
        }
    if task_name == ReconAiTask.PARAMETER_INPUT_ANALYSIS.value:
        return {
            "meta": meta,
            "params": [
                {
                    "name": "redirect",
                    "source": "query",
                    "context_url": "https://example.com/?redirect=/home",
                    "evidence_refs": ["route_inventory.csv:https://example.com/?redirect=/home"],
                }
            ],
        }
    if task_name == ReconAiTask.API_SURFACE_INFERENCE.value:
        return {
            "meta": meta,
            "api_candidates": [
                {
                    "path": "/api/v1/users",
                    "source": "route_inventory",
                    "method_hint": "GET",
                    "evidence_refs": ["api_surface.csv:/api/v1/users"],
                }
            ],
        }
    if task_name == ReconAiTask.HEADERS_TLS_SUMMARY.value:
        return {
            "meta": meta,
            "hosts": [
                {
                    "host": "https://example.com",
                    "header_score": "5",
                    "cookie_count": "1",
                    "cookie_secure": "1",
                    "evidence_refs": ["headers_detailed.csv:https://example.com"],
                }
            ],
        }
    if task_name == ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION.value:
        return {
            "meta": meta,
            "content_clusters": [
                {
                    "cluster_id": "content-1",
                    "host": "example.com",
                    "cluster_size": 3,
                    "template_hint": "shared_platform_template",
                    "evidence_ref": "content_clusters.csv:content-1",
                }
            ],
            "redirect_clusters": [
                {
                    "redirect_cluster_id": "redir-1",
                    "host": "example.com",
                    "redirect_target": "https://example.com/login",
                    "evidence_ref": "redirect_clusters.csv:redir-1",
                }
            ],
        }
    if task_name == ReconAiTask.ANOMALY_INTERPRETATION.value:
        return {
            "meta": meta,
            "anomalies": [
                {
                    "host": "x.example.com",
                    "status": "404",
                    "suspicious_host": True,
                    "catch_all_hint": False,
                    "shared_with_root": False,
                    "evidence_refs": ["content_clusters.csv:x.example.com"],
                }
            ],
        }
    if task_name == ReconAiTask.STAGE2_PREPARATION_SUMMARY.value:
        return {
            "meta": meta,
            "focus_hosts": ["example.com"],
            "risk_hypotheses": ["platform_alias"],
        }
    if task_name == ReconAiTask.STAGE3_PREPARATION_SUMMARY.value:
        return {
            "meta": meta,
            "focus_hosts": ["example.com"],
            "risk_hypotheses": ["platform_alias"],
            "stage3_readiness": {
                "status": "partially_ready_for_stage3",
                "missing_evidence": [],
                "unknowns": [],
                "recommended_follow_up": [],
                "coverage_scores": {
                    "route": 0.5,
                    "input_surface": 0.5,
                    "api_surface": 0.5,
                    "content_anomaly": 0.5,
                    "boundary_mapping": 0.5,
                },
            },
        }
    raise AssertionError(f"Unsupported task_name: {task_name}")


def _build_non_hypothesis_output(task_name: str) -> dict[str, Any]:
    if task_name == ReconAiTask.JS_FINDINGS_ANALYSIS.value:
        return {
            "summary": "ok",
            "findings": [
                {
                    "statement_type": "observation",
                    "category": "api_ref",
                    "value": "/api/v1/users",
                    "confidence": 0.5,
                    "evidence_refs": ["js:app.js"],
                }
            ],
        }
    if task_name == ReconAiTask.PARAMETER_INPUT_ANALYSIS.value:
        return {
            "params": [
                {
                    "statement_type": "observation",
                    "name": "id",
                    "category": "id_state",
                    "context_url": "https://example.com/user/1",
                    "confidence": 0.5,
                    "evidence_refs": ["route_inventory.csv"],
                }
            ]
        }
    if task_name == ReconAiTask.API_SURFACE_INFERENCE.value:
        return {
            "api_surface": [
                {
                    "statement_type": "inference",
                    "path": "/api/v1/users",
                    "api_type": "rest_like",
                    "auth_boundary_hint": "frontend_to_backend",
                    "confidence": 0.5,
                    "evidence_refs": ["api_surface.csv:/api/v1/users"],
                }
            ]
        }
    if task_name == ReconAiTask.HEADERS_TLS_SUMMARY.value:
        return {
            "summary": "ok",
            "controls": [
                {
                    "statement_type": "observation",
                    "host": "https://example.com",
                    "posture": "moderate",
                    "confidence": 0.5,
                    "evidence_refs": ["headers_detailed.csv:https://example.com"],
                }
            ],
        }
    if task_name == ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION.value:
        return {
            "summary": "ok",
            "clusters": [
                {
                    "statement_type": "inference",
                    "cluster_id": "cluster-1",
                    "interpretation": "unique_or_small_cluster",
                    "confidence": 0.5,
                    "evidence_refs": ["content_clusters.csv:cluster-1"],
                }
            ],
        }
    if task_name == ReconAiTask.ANOMALY_INTERPRETATION.value:
        return {
            "anomalies": [
                {
                    "statement_type": "hypothesis",
                    "host": "x.example.com",
                    "classification": "catch_all",
                    "recommendation": "review",
                    "confidence": 0.5,
                    "evidence_refs": ["anomaly_validation.md"],
                }
            ]
        }
    if task_name == ReconAiTask.STAGE2_PREPARATION_SUMMARY.value:
        return {
            "summary": "ok",
            "next_steps": [
                {
                    "statement_type": "hypothesis",
                    "step": "Validate host ownership",
                    "priority": "high",
                    "confidence": 0.5,
                    "evidence_refs": ["stage2_inputs.md"],
                }
            ],
        }
    if task_name == ReconAiTask.STAGE3_PREPARATION_SUMMARY.value:
        return {
            "summary": "ok",
            "next_steps": [
                {
                    "statement_type": "hypothesis",
                    "step": "Address missing evidence gaps",
                    "priority": "high",
                    "confidence": 0.5,
                    "evidence_refs": ["stage3_readiness.json"],
                }
            ],
        }
    raise AssertionError(f"Unsupported task_name: {task_name}")


def _build_report_output(task_name: str) -> dict[str, Any]:
    if task_name == ReconAiTask.JS_FINDINGS_ANALYSIS.value:
        return {"findings": [{"category": "api_ref", "value": "/api/v1/users"}]}
    if task_name == ReconAiTask.PARAMETER_INPUT_ANALYSIS.value:
        return {
            "params": [
                {"name": "redirect", "category": "redirect", "context_url": "https://example.com"}
            ]
        }
    if task_name == ReconAiTask.API_SURFACE_INFERENCE.value:
        return {
            "api_surface": [
                {
                    "path": "/api/v1/users",
                    "api_type": "rest_like",
                    "auth_boundary_hint": "frontend_to_backend",
                }
            ]
        }
    if task_name == ReconAiTask.HEADERS_TLS_SUMMARY.value:
        return {"controls": [{"host": "https://example.com", "posture": "moderate"}]}
    if task_name == ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION.value:
        return {
            "clusters": [
                {
                    "cluster_id": "cluster-1",
                    "interpretation": "shared_404_or_platform_template",
                }
            ]
        }
    if task_name == ReconAiTask.ANOMALY_INTERPRETATION.value:
        return {"anomalies": [{"host": "x.example.com", "classification": "catch_all"}]}
    if task_name == ReconAiTask.STAGE2_PREPARATION_SUMMARY.value:
        return {"next_steps": [{"priority": "high", "step": "Validate host ownership"}]}
    if task_name == ReconAiTask.STAGE3_PREPARATION_SUMMARY.value:
        return {"next_steps": [{"priority": "high", "step": "Address missing evidence gaps"}]}
    raise AssertionError(f"Unsupported task_name: {task_name}")


def _first_output_collection(output_payload: dict[str, Any]) -> list[dict[str, Any]]:
    collection_name = next(key for key in output_payload if isinstance(output_payload[key], list))
    return output_payload[collection_name]


def _schema_has_statement_type_const(schema: Any, expected_value: str) -> bool:
    if isinstance(schema, dict):
        if (
            schema.get("type") == "object"
            and "properties" in schema
            and isinstance(schema["properties"], dict)
            and "statement_type" in schema["properties"]
        ):
            statement_schema = schema["properties"]["statement_type"]
            if (
                isinstance(statement_schema, dict)
                and statement_schema.get("const") == expected_value
                and statement_schema.get("default") == expected_value
            ):
                return True

        return any(_schema_has_statement_type_const(value, expected_value) for value in schema.values())

    if isinstance(schema, list):
        return any(_schema_has_statement_type_const(item, expected_value) for item in schema)

    return False


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_examples_are_compatible_with_output_models(task_name: str) -> None:
    definitions = get_recon_ai_task_definitions()
    output_model = definitions[task_name]["expected_output_schema"]["title"]
    example_path = EXAMPLES_AI_OUTPUTS_DIR / f"{task_name}.example.json"
    payload = json.loads(example_path.read_text(encoding="utf-8"))

    validation = validate_recon_ai_payload(
        task_name=task_name,
        input_payload=_build_valid_input_payload(task_name),
        output_payload=payload,
    )

    assert output_model
    assert validation["input"]["is_valid"] is True
    assert validation["output"]["is_valid"] is True


def test_schema_export_contains_all_8_tasks_with_required_keys(tmp_path: Path) -> None:
    registry = get_recon_ai_task_definitions()
    assert len(RECON_AI_TASKS) == 8
    assert set(registry.keys()) == set(RECON_AI_TASKS)

    for task_name in RECON_AI_TASKS:
        item = registry[task_name]
        assert item["task_name"] == task_name
        assert "input_schema" in item
        assert "expected_output_schema" in item
        assert item["validator"] == "pydantic-v2:model_validate"
        assert item["persistence_mapping"]["raw"].endswith(".json")
        assert item["persistence_mapping"]["normalized"].endswith(".json")
        assert item["report_section_mapping"]

    output_file = export_recon_ai_schemas(tmp_path)
    exported = json.loads(output_file.read_text(encoding="utf-8"))
    assert set(exported.keys()) == set(RECON_AI_TASKS)


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_schema_export_includes_full_ai_persistence_bundle_mapping(task_name: str) -> None:
    registry = get_recon_ai_task_definitions()
    persistence = registry[task_name]["persistence_mapping"]
    assert set(persistence.keys()) == {
        "raw",
        "normalized",
        "input_bundle",
        "validation",
        "rendered_prompt",
    }
    assert persistence["raw"] == f"ai_{task_name}_raw.json"
    assert persistence["normalized"] == f"ai_{task_name}_normalized.json"
    assert persistence["input_bundle"] == f"ai_{task_name}_input_bundle.json"
    assert persistence["validation"] == f"ai_{task_name}_validation.json"
    assert persistence["rendered_prompt"] == f"ai_{task_name}_rendered_prompt.md"


def test_schema_export_persistence_mapping_is_in_sync_with_stage1_contract_artifacts() -> None:
    registry = get_recon_ai_task_definitions()
    baseline = set(STAGE1_BASELINE_ARTIFACTS)

    for task_name in RECON_AI_TASKS:
        persistence = registry[task_name]["persistence_mapping"]
        for artifact_name in persistence.values():
            assert artifact_name in baseline, f"{artifact_name} must be declared in Stage1 baseline contract"


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_schema_export_maps_tasks_to_expected_report_sections(task_name: str) -> None:
    registry = get_recon_ai_task_definitions()
    assert registry[task_name]["report_section_mapping"] == [TASK_EXPECTED_SECTION[task_name]]


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_input_rejects_wrong_meta_task_for_all_tasks(task_name: str) -> None:
    payload = _build_valid_input_payload(task_name)
    wrong_task = next(name for name in RECON_AI_TASKS if name != task_name)
    payload["meta"]["task"] = wrong_task

    validation = validate_recon_ai_payload(
        task_name=task_name,
        input_payload=payload,
        output_payload=_build_non_hypothesis_output(task_name),
    )

    assert validation["input"]["is_valid"] is False


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_input_rejects_broken_run_or_job_link_for_all_tasks(task_name: str) -> None:
    payload = _build_valid_input_payload(task_name)
    broken_run = dict(payload)
    broken_run["meta"] = dict(payload["meta"])
    broken_run["meta"]["run_link"] = "recon://runs/another"

    broken_job = dict(payload)
    broken_job["meta"] = dict(payload["meta"])
    broken_job["meta"]["job_link"] = "recon://jobs/another"

    run_validation = validate_recon_ai_payload(
        task_name=task_name,
        input_payload=broken_run,
        output_payload=_build_non_hypothesis_output(task_name),
    )
    job_validation = validate_recon_ai_payload(
        task_name=task_name,
        input_payload=broken_job,
        output_payload=_build_non_hypothesis_output(task_name),
    )

    assert run_validation["input"]["is_valid"] is False
    assert job_validation["input"]["is_valid"] is False


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_output_rejects_invalid_confidence_range_for_all_tasks(task_name: str) -> None:
    payload = _build_non_hypothesis_output(task_name)
    _first_output_collection(payload)[0]["confidence"] = 1.1

    validation = validate_recon_ai_payload(
        task_name=task_name,
        input_payload=_build_valid_input_payload(task_name),
        output_payload=payload,
    )

    assert validation["output"]["is_valid"] is False


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_output_rejects_type_coercion_for_all_tasks(task_name: str) -> None:
    payload = _build_non_hypothesis_output(task_name)
    _first_output_collection(payload)[0]["confidence"] = "0.5"

    validation = validate_recon_ai_payload(
        task_name=task_name,
        input_payload=_build_valid_input_payload(task_name),
        output_payload=payload,
    )

    assert validation["output"]["is_valid"] is False


@pytest.mark.parametrize("task_name", NON_HYPOTHESIS_TASKS)
def test_output_requires_evidence_refs_for_non_hypothesis_all_tasks(task_name: str) -> None:
    payload = _build_non_hypothesis_output(task_name)
    _first_output_collection(payload)[0]["evidence_refs"] = []

    validation = validate_recon_ai_payload(
        task_name=task_name,
        input_payload=_build_valid_input_payload(task_name),
        output_payload=payload,
    )

    assert validation["output"]["is_valid"] is False


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_output_rejects_blank_or_whitespace_evidence_refs_for_all_tasks(task_name: str) -> None:
    payload = _build_non_hypothesis_output(task_name)
    _first_output_collection(payload)[0]["evidence_refs"] = ["   "]

    validation = validate_recon_ai_payload(
        task_name=task_name,
        input_payload=_build_valid_input_payload(task_name),
        output_payload=payload,
    )

    assert validation["output"]["is_valid"] is False


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_input_rejects_type_coercion_for_all_tasks(task_name: str) -> None:
    payload = _build_valid_input_payload(task_name)
    payload["meta"]["run_id"] = 123

    validation = validate_recon_ai_payload(
        task_name=task_name,
        input_payload=payload,
        output_payload=_build_non_hypothesis_output(task_name),
    )

    assert validation["input"]["is_valid"] is False


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_to_report_notes_maps_all_8_tasks(task_name: str) -> None:
    registry = get_recon_ai_task_definitions()
    notes = to_report_notes(task_name, _build_report_output(task_name))

    assert notes
    assert all(note["section_id"] == registry[task_name]["report_section_mapping"][0] for note in notes)
    assert all(note["note"] for note in notes)


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_output_rejects_wrong_statement_type_for_each_task(task_name: str) -> None:
    payload = _build_non_hypothesis_output(task_name)
    wrong_statement_type = (
        "inference" if TASK_EXPECTED_STATEMENT_TYPE[task_name] != "inference" else "observation"
    )
    _first_output_collection(payload)[0]["statement_type"] = wrong_statement_type

    validation = validate_recon_ai_payload(
        task_name=task_name,
        input_payload=_build_valid_input_payload(task_name),
        output_payload=payload,
    )

    assert validation["output"]["is_valid"] is False


@pytest.mark.parametrize("task_name", RECON_AI_TASKS)
def test_schema_export_contains_fixed_statement_type_for_each_output(task_name: str) -> None:
    registry = get_recon_ai_task_definitions()
    output_schema = registry[task_name]["expected_output_schema"]
    expected_statement_type = TASK_EXPECTED_STATEMENT_TYPE[task_name]

    assert _schema_has_statement_type_const(output_schema, expected_statement_type)


@pytest.mark.parametrize(
    ("task_name", "payload"),
    (
        (
            ReconAiTask.JS_FINDINGS_ANALYSIS.value,
            {
                "findings": [
                    {
                        "category": "api_ref",
                        "value": "https://example.com/api?token=very-secret",
                    }
                ]
            },
        ),
        (
            ReconAiTask.PARAMETER_INPUT_ANALYSIS.value,
            {
                "params": [
                    {
                        "name": "redirect",
                        "category": "redirect",
                        "context_url": "https://example.com/cb?token=very-secret&next=/home",
                    }
                ]
            },
        ),
        (
            ReconAiTask.API_SURFACE_INFERENCE.value,
            {
                "api_surface": [
                    {
                        "path": "https://example.com/api/v1/users?api_key=very-secret",
                        "api_type": "rest_like",
                        "auth_boundary_hint": "frontend_to_backend",
                    }
                ]
            },
        ),
        (
            ReconAiTask.HEADERS_TLS_SUMMARY.value,
            {
                "controls": [
                    {
                        "host": "https://example.com?token=very-secret",
                        "posture": "moderate",
                    }
                ]
            },
        ),
        (
            ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION.value,
            {
                "clusters": [
                    {
                        "cluster_id": "cluster-1",
                        "interpretation": "see https://example.com/cluster?token=very-secret",
                    }
                ]
            },
        ),
        (
            ReconAiTask.ANOMALY_INTERPRETATION.value,
            {
                "anomalies": [
                    {
                        "host": "https://x.example.com/?session=very-secret",
                        "classification": "catch_all",
                    }
                ]
            },
        ),
        (
            ReconAiTask.STAGE2_PREPARATION_SUMMARY.value,
            {
                "next_steps": [
                    {
                        "priority": "high",
                        "step": "validate callback token=very-secret before next run",
                    }
                ]
            },
        ),
        (
            ReconAiTask.STAGE3_PREPARATION_SUMMARY.value,
            {
                "next_steps": [
                    {
                        "priority": "high",
                        "step": "validate callback token=very-secret before Stage 3",
                    }
                ]
            },
        ),
    ),
)
def test_to_report_notes_redacts_sensitive_query_values(task_name: str, payload: dict[str, Any]) -> None:
    notes = to_report_notes(task_name, payload)
    assert notes
    serialized = json.dumps(notes)
    assert "very-secret" not in serialized
    assert "[REDACTED]" in serialized or "%5BREDACTED%5D" in serialized
