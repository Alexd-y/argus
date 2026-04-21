from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, Field, ValidationError

from .common import ReconAiTask

logger = logging.getLogger(__name__)

RECON_AI_TASKS: tuple[str, ...] = tuple(t.value for t in ReconAiTask)

_TASK_DEFINITIONS: dict[str, dict[str, Any]] = {
    ReconAiTask.ROUTE_DISCOVERY.value: {
        "task_name": ReconAiTask.ROUTE_DISCOVERY.value,
        "description": "Discover application routes and URL patterns from recon data",
        "required_input_keys": ["meta", "bundle"],
        "expected_output_keys": ["routes"],
    },
    ReconAiTask.JS_ANALYSIS.value: {
        "task_name": ReconAiTask.JS_ANALYSIS.value,
        "description": "Analyze JavaScript files for endpoints, secrets, and API calls",
        "required_input_keys": ["meta", "bundle"],
        "expected_output_keys": ["js_findings"],
    },
    ReconAiTask.PARAM_DISCOVERY.value: {
        "task_name": ReconAiTask.PARAM_DISCOVERY.value,
        "description": "Discover query/body parameters from crawl and JS analysis",
        "required_input_keys": ["meta", "bundle"],
        "expected_output_keys": ["parameters"],
    },
    ReconAiTask.API_SURFACE.value: {
        "task_name": ReconAiTask.API_SURFACE.value,
        "description": "Map API surface area including endpoints, methods, and auth requirements",
        "required_input_keys": ["meta", "bundle"],
        "expected_output_keys": ["api_endpoints"],
    },
    ReconAiTask.STAGE3_READINESS.value: {
        "task_name": ReconAiTask.STAGE3_READINESS.value,
        "description": "Assess readiness for Stage 3 vulnerability analysis",
        "required_input_keys": ["meta", "bundle"],
        "expected_output_keys": ["ready", "blocking_reasons"],
    },
}


class _RouteDiscoveryOutput(BaseModel):
    routes: list[dict[str, Any]] = Field(default_factory=list)


class _JsAnalysisOutput(BaseModel):
    js_findings: list[dict[str, Any]] = Field(default_factory=list)


class _ParamDiscoveryOutput(BaseModel):
    parameters: list[dict[str, Any]] = Field(default_factory=list)


class _ApiSurfaceOutput(BaseModel):
    api_endpoints: list[dict[str, Any]] = Field(default_factory=list)


class _Stage3ReadinessOutput(BaseModel):
    ready: bool = False
    blocking_reasons: list[str] = Field(default_factory=list)


_OUTPUT_MODELS: dict[str, type[BaseModel]] = {
    ReconAiTask.ROUTE_DISCOVERY.value: _RouteDiscoveryOutput,
    ReconAiTask.JS_ANALYSIS.value: _JsAnalysisOutput,
    ReconAiTask.PARAM_DISCOVERY.value: _ParamDiscoveryOutput,
    ReconAiTask.API_SURFACE.value: _ApiSurfaceOutput,
    ReconAiTask.STAGE3_READINESS.value: _Stage3ReadinessOutput,
}


def get_recon_ai_task_definitions() -> dict[str, dict[str, Any]]:
    """Return task definitions for all recon AI tasks with schema metadata."""
    return {k: dict(v) for k, v in _TASK_DEFINITIONS.items()}


def validate_recon_ai_payload(
    task_name: str, input_payload: dict, output_payload: dict
) -> dict[str, Any]:
    """Validate recon AI input/output payloads against Pydantic models.

    Returns a dict with ``input`` and ``output`` validation results
    (each containing ``is_valid: bool`` and ``errors: list[str]``).
    """
    input_errors: list[str] = []
    output_errors: list[str] = []

    definition = _TASK_DEFINITIONS.get(task_name)
    if definition is None:
        input_errors.append(f"Unknown recon AI task: {task_name}")
        return {
            "task_name": task_name,
            "input": {"is_valid": False, "errors": input_errors},
            "output": {"is_valid": False, "errors": [f"Unknown recon AI task: {task_name}"]},
        }

    for key in definition.get("required_input_keys", []):
        if key not in input_payload:
            input_errors.append(f"Missing required input key: {key}")

    model_cls = _OUTPUT_MODELS.get(task_name)
    if model_cls is not None:
        try:
            model_cls.model_validate(output_payload)
        except ValidationError as exc:
            output_errors.extend(err["msg"] for err in exc.errors())
    else:
        output_errors.append(f"No output schema defined for task: {task_name}")

    return {
        "task_name": task_name,
        "input": {"is_valid": len(input_errors) == 0, "errors": input_errors},
        "output": {"is_valid": len(output_errors) == 0, "errors": output_errors},
    }
