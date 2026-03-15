"""Task registry for threat modeling AI tasks — definitions, validation, schema export.

Separate from recon AI task registry. Each task has input/output schemas,
versioned prompt templates, and Pydantic validators.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.prompts.threat_modeling_prompts import get_threat_modeling_prompt
from app.schemas.ai.common import ThreatModelingAiTask, validate_with_model
from app.schemas.threat_modeling.ai_tasks import (
    TM_TASK_INPUT_MODELS,
    TM_TASK_OUTPUT_MODELS,
)

# Ordered task list — execution order for pipeline
THREAT_MODELING_AI_TASKS: tuple[str, ...] = (
    ThreatModelingAiTask.CRITICAL_ASSETS.value,
    ThreatModelingAiTask.TRUST_BOUNDARIES.value,
    ThreatModelingAiTask.ATTACKER_PROFILES.value,
    ThreatModelingAiTask.ENTRY_POINTS.value,
    ThreatModelingAiTask.APPLICATION_FLOWS.value,
    ThreatModelingAiTask.THREAT_SCENARIOS.value,
    ThreatModelingAiTask.SCENARIO_SCORING.value,
    ThreatModelingAiTask.TESTING_ROADMAP.value,
    ThreatModelingAiTask.REPORT_SUMMARY.value,
)


def _persistence_mapping(task_name: str) -> dict[str, str]:
    """Build persistence file mapping for a threat modeling task."""
    prefix = f"ai_tm_{task_name}"
    return {
        "raw": f"{prefix}_raw.json",
        "normalized": f"{prefix}_normalized.json",
        "input_bundle": f"{prefix}_input_bundle.json",
        "validation": f"{prefix}_validation.json",
        "rendered_prompt": f"{prefix}_rendered_prompt.md",
    }


def _definition(task_name: str) -> dict[str, Any]:
    """Return task definition for the given threat modeling task."""
    if task_name not in THREAT_MODELING_AI_TASKS:
        raise ValueError(f"Unknown threat modeling AI task: {task_name}")
    task_enum = ThreatModelingAiTask(task_name)
    input_model = TM_TASK_INPUT_MODELS[task_enum]
    output_model = TM_TASK_OUTPUT_MODELS[task_enum]
    prompt_template = get_threat_modeling_prompt(task_name)
    return {
        "input_model": input_model,
        "output_model": output_model,
        "prompt_template": prompt_template,
        "persistence": _persistence_mapping(task_name),
    }


def get_threat_modeling_ai_task_definitions() -> dict[str, dict[str, Any]]:
    """Return JSON-schema friendly definitions for all threat modeling AI tasks."""
    payload: dict[str, dict[str, Any]] = {}
    for task_name in THREAT_MODELING_AI_TASKS:
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
        }
    return payload


def validate_threat_modeling_ai_payload(
    task_name: str,
    input_payload: dict[str, Any],
    output_payload: dict[str, Any],
) -> dict[str, Any]:
    """Validate input/output payloads for a specific threat modeling AI task."""
    definition = _definition(task_name)
    input_errors = validate_with_model(definition["input_model"], input_payload)
    output_errors = validate_with_model(definition["output_model"], output_payload)
    return {
        "task_name": task_name,
        "input": {"is_valid": len(input_errors) == 0, "errors": input_errors},
        "output": {"is_valid": len(output_errors) == 0, "errors": output_errors},
    }


def export_threat_modeling_ai_schemas(output_path: str | Path) -> Path:
    """Export complete threat modeling AI schema registry to a JSON file."""
    destination = Path(output_path)
    if destination.is_dir():
        destination = destination / "threat_modeling_ai_tasks.schemas.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(get_threat_modeling_ai_task_definitions(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return destination
