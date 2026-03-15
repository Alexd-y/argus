"""Schema export and task registry for recon and vulnerability analysis AI tasks."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from pydantic import BaseModel

from app.schemas.ai.anomaly_interpretation import (
    AnomalyInterpretationInput,
    AnomalyInterpretationOutput,
)
from app.schemas.ai.api_surface_inference import (
    ApiSurfaceInferenceInput,
    ApiSurfaceInferenceOutput,
)
from app.schemas.ai.common import ReconAiTask, ReportSectionId, validate_with_model
from app.schemas.ai.content_similarity_interpretation import (
    ContentSimilarityInterpretationInput,
    ContentSimilarityInterpretationOutput,
)
from app.schemas.ai.headers_tls_summary import HeadersTlsSummaryInput, HeadersTlsSummaryOutput
from app.schemas.ai.js_findings_analysis import JsFindingsAnalysisInput, JsFindingsAnalysisOutput
from app.schemas.ai.parameter_input_analysis import (
    ParameterInputAnalysisInput,
    ParameterInputAnalysisOutput,
)
from app.schemas.ai.stage2_preparation_summary import (
    Stage2PreparationSummaryInput,
    Stage2PreparationSummaryOutput,
)
from app.schemas.ai.stage3_preparation_summary import (
    Stage3PreparationSummaryInput,
    Stage3PreparationSummaryOutput,
)

# Keep ordering stable and explicit (REC-008: 8 tasks including stage3_preparation_summary).
RECON_AI_TASKS: tuple[str, ...] = (
    ReconAiTask.JS_FINDINGS_ANALYSIS.value,
    ReconAiTask.PARAMETER_INPUT_ANALYSIS.value,
    ReconAiTask.API_SURFACE_INFERENCE.value,
    ReconAiTask.HEADERS_TLS_SUMMARY.value,
    ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION.value,
    ReconAiTask.ANOMALY_INTERPRETATION.value,
    ReconAiTask.STAGE2_PREPARATION_SUMMARY.value,
    ReconAiTask.STAGE3_PREPARATION_SUMMARY.value,
)


class _TaskDefinition(dict):
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    prompt_template: str
    persistence: dict[str, str]
    report_sections: list[str]


_TASK_DEFINITIONS: dict[str, _TaskDefinition] = {
    ReconAiTask.JS_FINDINGS_ANALYSIS.value: {
        "input_model": JsFindingsAnalysisInput,
        "output_model": JsFindingsAnalysisOutput,
        "prompt_template": (
            "Analyze JavaScript-derived recon findings. Keep only evidence-grounded statements, "
            "classify into known categories, and include confidence [0..1] with evidence_refs."
        ),
        "persistence": {
            "raw": "ai_js_findings_analysis_raw.json",
            "normalized": "ai_js_findings_analysis_normalized.json",
            "input_bundle": "ai_js_findings_analysis_input_bundle.json",
            "validation": "ai_js_findings_analysis_validation.json",
            "rendered_prompt": "ai_js_findings_analysis_rendered_prompt.md",
        },
        "report_sections": [ReportSectionId.JS_FRONTEND_ANALYSIS.value],
    },
    ReconAiTask.PARAMETER_INPUT_ANALYSIS.value: {
        "input_model": ParameterInputAnalysisInput,
        "output_model": ParameterInputAnalysisOutput,
        "prompt_template": (
            "Analyze discovered URL/form/path parameters. Classify each parameter category using "
            "allowed enum values and preserve context_url + evidence_refs."
        ),
        "persistence": {
            "raw": "ai_parameter_input_analysis_raw.json",
            "normalized": "ai_parameter_input_analysis_normalized.json",
            "input_bundle": "ai_parameter_input_analysis_input_bundle.json",
            "validation": "ai_parameter_input_analysis_validation.json",
            "rendered_prompt": "ai_parameter_input_analysis_rendered_prompt.md",
        },
        "report_sections": [ReportSectionId.PARAMS_INPUT_SURFACES.value],
    },
    ReconAiTask.API_SURFACE_INFERENCE.value: {
        "input_model": ApiSurfaceInferenceInput,
        "output_model": ApiSurfaceInferenceOutput,
        "prompt_template": (
            "Infer API surface from discovered candidates. Output only enum-safe api_type/auth hints, "
            "confidence [0..1], and evidence_refs for non-hypothesis statements."
        ),
        "persistence": {
            "raw": "ai_api_surface_inference_raw.json",
            "normalized": "ai_api_surface_inference_normalized.json",
            "input_bundle": "ai_api_surface_inference_input_bundle.json",
            "validation": "ai_api_surface_inference_validation.json",
            "rendered_prompt": "ai_api_surface_inference_rendered_prompt.md",
        },
        "report_sections": [ReportSectionId.API_SURFACE_MAPPING.value],
    },
    ReconAiTask.HEADERS_TLS_SUMMARY.value: {
        "input_model": HeadersTlsSummaryInput,
        "output_model": HeadersTlsSummaryOutput,
        "prompt_template": (
            "Summarize headers/cookies/TLS posture by host. Use strong/moderate/weak enum only and "
            "attach evidence_refs for each control statement."
        ),
        "persistence": {
            "raw": "ai_headers_tls_summary_raw.json",
            "normalized": "ai_headers_tls_summary_normalized.json",
            "input_bundle": "ai_headers_tls_summary_input_bundle.json",
            "validation": "ai_headers_tls_summary_validation.json",
            "rendered_prompt": "ai_headers_tls_summary_rendered_prompt.md",
        },
        "report_sections": [ReportSectionId.HEADERS_TLS.value],
    },
    ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION.value: {
        "input_model": ContentSimilarityInterpretationInput,
        "output_model": ContentSimilarityInterpretationOutput,
        "prompt_template": (
            "Interpret content and redirect clustering artifacts. Use only allowed interpretation enum "
            "values and include confidence + evidence_refs."
        ),
        "persistence": {
            "raw": "ai_content_similarity_interpretation_raw.json",
            "normalized": "ai_content_similarity_interpretation_normalized.json",
            "input_bundle": "ai_content_similarity_interpretation_input_bundle.json",
            "validation": "ai_content_similarity_interpretation_validation.json",
            "rendered_prompt": "ai_content_similarity_interpretation_rendered_prompt.md",
        },
        "report_sections": [ReportSectionId.CONTENT_ROUTING.value],
    },
    ReconAiTask.ANOMALY_INTERPRETATION.value: {
        "input_model": AnomalyInterpretationInput,
        "output_model": AnomalyInterpretationOutput,
        "prompt_template": (
            "Classify anomalies using approved taxonomy only. Provide bounded confidence and "
            "recommended follow-up actions with evidence_refs."
        ),
        "persistence": {
            "raw": "ai_anomaly_interpretation_raw.json",
            "normalized": "ai_anomaly_interpretation_normalized.json",
            "input_bundle": "ai_anomaly_interpretation_input_bundle.json",
            "validation": "ai_anomaly_interpretation_validation.json",
            "rendered_prompt": "ai_anomaly_interpretation_rendered_prompt.md",
        },
        "report_sections": [ReportSectionId.ANOMALY_VALIDATION.value],
    },
    ReconAiTask.STAGE2_PREPARATION_SUMMARY.value: {
        "input_model": Stage2PreparationSummaryInput,
        "output_model": Stage2PreparationSummaryOutput,
        "prompt_template": (
            "Produce Stage-2 preparation summary: prioritized next steps, confidence, and strict "
            "evidence_refs linked to Stage-1 artifacts."
        ),
        "persistence": {
            "raw": "ai_stage2_preparation_summary_raw.json",
            "normalized": "ai_stage2_preparation_summary_normalized.json",
            "input_bundle": "ai_stage2_preparation_summary_input_bundle.json",
            "validation": "ai_stage2_preparation_summary_validation.json",
            "rendered_prompt": "ai_stage2_preparation_summary_rendered_prompt.md",
        },
        "report_sections": [ReportSectionId.STAGE2_PREP.value],
    },
    ReconAiTask.STAGE3_PREPARATION_SUMMARY.value: {
        "input_model": Stage3PreparationSummaryInput,
        "output_model": Stage3PreparationSummaryOutput,
        "prompt_template": (
            "Produce Stage-3 preparation summary from stage3_readiness: prioritized next steps for "
            "penetration testing readiness, confidence, and strict evidence_refs linked to Stage-1/2 artifacts."
        ),
        "persistence": {
            "raw": "ai_stage3_preparation_summary_raw.json",
            "normalized": "ai_stage3_preparation_summary_normalized.json",
            "input_bundle": "ai_stage3_preparation_summary_input_bundle.json",
            "validation": "ai_stage3_preparation_summary_validation.json",
            "rendered_prompt": "ai_stage3_preparation_summary_rendered_prompt.md",
        },
        "report_sections": [ReportSectionId.STAGE3_READINESS.value],
    },
}


_SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|token|secret|api[_-]?key|authorization|cookie|session|auth|code|key)",
    re.IGNORECASE,
)
_SENSITIVE_QUERY_VALUE_RE = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|authorization|cookie|session|auth|code|key)=([^&#\s]+)"
)


def _sanitize_note_value(value: str) -> str:
    parsed = urlparse(value.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        return value
    if not parsed.query:
        return value

    safe_pairs: list[tuple[str, str]] = []
    for key, inner_value in parse_qsl(parsed.query, keep_blank_values=True):
        if _SENSITIVE_KEY_RE.search(key):
            safe_pairs.append((key, "[REDACTED]"))
        else:
            safe_pairs.append((key, inner_value))
    return urlunparse(parsed._replace(query=urlencode(safe_pairs, doseq=True)))


def _sanitize_note_text(text: str) -> str:
    # Keep report notes useful, but redact secret-like query values in URLs.
    sanitized = " ".join(_sanitize_note_value(part) for part in str(text).split())
    return _SENSITIVE_QUERY_VALUE_RE.sub(r"\1=[REDACTED]", sanitized)


def _definition(task_name: str) -> _TaskDefinition:
    if task_name not in _TASK_DEFINITIONS:
        raise ValueError(f"Unknown recon AI task: {task_name}")
    return _TASK_DEFINITIONS[task_name]


def get_recon_ai_task_definitions() -> dict[str, dict[str, Any]]:
    """Return JSON-schema friendly definitions for all recon AI tasks."""
    payload: dict[str, dict[str, Any]] = {}
    for task_name in RECON_AI_TASKS:
        definition = _definition(task_name)
        input_model = definition["input_model"]
        output_model = definition["output_model"]
        payload[task_name] = {
            "task_name": task_name,
            "input_schema": input_model.model_json_schema(),
            "prompt_template": definition["prompt_template"],
            "expected_output_schema": output_model.model_json_schema(),
            "validator": "pydantic-v2:model_validate",
            "persistence_mapping": definition["persistence"],
            "report_section_mapping": definition["report_sections"],
        }
    return payload


def validate_recon_ai_payload(
    task_name: str,
    input_payload: dict[str, Any],
    output_payload: dict[str, Any],
) -> dict[str, Any]:
    """Validate input/output payloads for a specific recon AI task."""
    definition = _definition(task_name)
    input_errors = validate_with_model(definition["input_model"], input_payload)
    output_errors = validate_with_model(definition["output_model"], output_payload)
    return {
        "task_name": task_name,
        "input": {"is_valid": len(input_errors) == 0, "errors": input_errors},
        "output": {"is_valid": len(output_errors) == 0, "errors": output_errors},
    }


def get_vulnerability_analysis_ai_task_definitions() -> dict[str, dict[str, Any]]:
    """Return JSON-schema friendly definitions for all vulnerability analysis AI tasks."""
    from src.recon.vulnerability_analysis.ai_task_registry import get_va_ai_task_definitions

    return get_va_ai_task_definitions()


def export_recon_ai_schemas(output_path: str | Path) -> Path:
    """Export complete recon AI schema registry to a JSON file."""
    destination = Path(output_path)
    if destination.is_dir():
        destination = destination / "recon_ai_tasks.schemas.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(get_recon_ai_task_definitions(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return destination


def to_report_notes(task_name: str, output_payload: dict[str, Any]) -> list[dict[str, str]]:
    """Convert task output to report-section note snippets."""
    sections = _definition(task_name)["report_sections"]
    notes: list[dict[str, str]] = []
    section_id = sections[0]

    def _note(text: str) -> None:
        if text:
            notes.append({"section_id": section_id, "note": _sanitize_note_text(text)})

    if task_name == ReconAiTask.JS_FINDINGS_ANALYSIS.value:
        for item in output_payload.get("findings", [])[:20]:
            _note(f"js:{item.get('category', '')} => {item.get('value', '')}")
    elif task_name == ReconAiTask.PARAMETER_INPUT_ANALYSIS.value:
        for item in output_payload.get("params", [])[:20]:
            _note(
                f"param:{item.get('name', '')} category={item.get('category', '')} "
                f"url={item.get('context_url', '')}",
            )
    elif task_name == ReconAiTask.API_SURFACE_INFERENCE.value:
        for item in output_payload.get("api_surface", [])[:20]:
            _note(
                f"api:{item.get('path', '')} type={item.get('api_type', '')} "
                f"auth={item.get('auth_boundary_hint', '')}",
            )

    elif task_name == ReconAiTask.HEADERS_TLS_SUMMARY.value:
        for item in output_payload.get("controls", [])[:20]:
            _note(f"{item.get('host', '')}: posture={item.get('posture', '')}")
    elif task_name == ReconAiTask.CONTENT_SIMILARITY_INTERPRETATION.value:
        for item in output_payload.get("clusters", [])[:20]:
            _note(
                f"cluster:{item.get('cluster_id', '')} "
                f"interpretation={item.get('interpretation', '')}",
            )
    elif task_name == ReconAiTask.ANOMALY_INTERPRETATION.value:
        for item in output_payload.get("anomalies", [])[:20]:
            _note(f"{item.get('host', '')}: {item.get('classification', '')}")
    elif task_name == ReconAiTask.STAGE2_PREPARATION_SUMMARY.value:
        for item in output_payload.get("next_steps", [])[:20]:
            _note(f"{item.get('priority', '')}: {item.get('step', '')}")
    elif task_name == ReconAiTask.STAGE3_PREPARATION_SUMMARY.value:
        for item in output_payload.get("next_steps", [])[:20]:
            _note(f"{item.get('priority', '')}: {item.get('step', '')}")
    else:
        summary = output_payload.get("summary")
        if isinstance(summary, str) and summary:
            _note(summary)

    return notes
