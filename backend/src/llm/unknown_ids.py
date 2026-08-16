"""Unknown ID policy for the unified LLM gateway (master prompt §19.2).

Production rejects unknown prompt/schema IDs. LAB continues with a generated
artifact schema so offensive/research tasks are not refused.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.eval.rates import record_unknown_id_check
from src.execution_mode.mode import ExecutionMode
from src.llm.prompts.prompts_pack import PROMPTS_BY_ID
from src.llm.schemas import LlmRequest

LAB_GENERATED_ARTIFACT_SCHEMA_ID = "lab_generated_artifact_v1"

LAB_GENERATED_ARTIFACT_SCHEMA: dict[str, object] = {
    "type": "object",
    "additionalProperties": True,
}


@dataclass(frozen=True)
class UnknownIdDecision:
    unknown_ids: tuple[str, ...]
    reject: bool
    lab_generated_schema: bool
    resolved_schema_id: str | None


def classify_unknown_ids(
    request: LlmRequest,
    *,
    known_schema_ids: set[str],
) -> UnknownIdDecision:
    unknown: list[str] = []
    prompt_id = (request.prompt_id or "").strip()
    if prompt_id and prompt_id not in PROMPTS_BY_ID:
        unknown.append(f"prompt_id:{prompt_id}")

    schema_id = (request.response_schema_id or "").strip() or None
    schema_unknown = bool(schema_id and schema_id not in known_schema_ids)
    if schema_unknown and schema_id:
        unknown.append(f"schema_id:{schema_id}")

    is_unknown = bool(unknown)
    record_unknown_id_check(unknown=is_unknown)

    lab = request.execution_mode == ExecutionMode.LAB_UNRESTRICTED
    if not is_unknown:
        return UnknownIdDecision(
            unknown_ids=(),
            reject=False,
            lab_generated_schema=False,
            resolved_schema_id=schema_id,
        )
    if lab:
        resolved = schema_id
        generated = False
        if schema_unknown:
            resolved = LAB_GENERATED_ARTIFACT_SCHEMA_ID
            generated = True
        return UnknownIdDecision(
            unknown_ids=tuple(unknown),
            reject=False,
            lab_generated_schema=generated,
            resolved_schema_id=resolved,
        )
    return UnknownIdDecision(
        unknown_ids=tuple(unknown),
        reject=True,
        lab_generated_schema=False,
        resolved_schema_id=schema_id,
    )
