"""Agent output contracts — tolerant validators + JSON schemas.

Ported from ``_external/Cairn/cairn/src/cairn/dispatcher/contracts.py`` (AGPL-3.0),
preserving all format tolerance (wrapped ``{"accepted": ...}`` envelopes, bare
payloads, singular ``intent`` → ``intents``, ``max_intents`` truncation, and the
mutual exclusion of ``complete`` and ``intents``).

Adds Pydantic models and their ``model_json_schema()`` exports so the schemas can
be passed to ``call_llm_unified`` as ``response_format`` (WRB-002).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from src.cairn.output_parser import extract_json_object


def parse_json_output(stdout: str) -> dict[str, Any]:
    return extract_json_object(stdout)


# --- envelope handling -------------------------------------------------------


def _unwrap_wrapped_payload(
    payload: dict[str, Any],
) -> tuple[bool | None, dict[str, Any] | None]:
    accepted = payload.get("accepted")
    if accepted is False:
        return False, None
    if accepted is True:
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ValueError("data must be an object")
        return True, data
    return None, None


def _is_dict(value: Any) -> bool:
    return isinstance(value, dict)


def _looks_like_reason_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if keys == {"complete"}:
        complete = payload["complete"]
        return isinstance(complete, dict) and "from" in complete and "description" in complete
    if keys == {"intents"}:
        return isinstance(payload["intents"], list)
    if keys == {"intent"}:
        intent = payload["intent"]
        return isinstance(intent, dict) and "from" in intent and "description" in intent
    return False


def _looks_like_bootstrap_execute_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict) or set(payload) != {"fact", "complete"}:
        return False
    return _is_dict(payload.get("fact")) and _is_dict(payload.get("complete"))


def _looks_like_bootstrap_conclude_data(payload: dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return False
    keys = set(payload)
    if keys not in ({"fact"}, {"fact", "complete"}):
        return False
    return _is_dict(payload.get("fact"))


def _looks_like_explore_data(payload: dict[str, Any]) -> bool:
    return isinstance(payload, dict) and set(payload) == {"description"}


# --- validators --------------------------------------------------------------


def validate_reason_payload(
    payload: dict[str, Any],
    open_intents_empty: bool,
    max_intents: int,
) -> tuple[str, dict[str, Any] | list[dict[str, Any]] | None]:
    """Return ``(kind, data)`` where kind is rejected|complete|intents|noop."""
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_reason_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    complete = data.get("complete")
    intents = data.get("intents")
    # backward compat: accept singular "intent" key from LLMs
    if intents is None:
        singular = data.get("intent")
        if isinstance(singular, dict):
            intents = [singular]
    if complete is not None:
        if intents is not None:
            raise ValueError("complete and intents cannot coexist")
        if (
            not isinstance(complete, dict)
            or "from" not in complete
            or "description" not in complete
        ):
            raise ValueError("invalid complete payload")
        return "complete", complete
    if intents is not None:
        if not isinstance(intents, list):
            raise ValueError("intents must be an array")
        for i, intent in enumerate(intents):
            if not isinstance(intent, dict) or "from" not in intent or "description" not in intent:
                raise ValueError(f"invalid intent at index {i}")
        if not intents and open_intents_empty:
            raise ValueError("intents must not be empty when open_intents is empty")
        intents = intents[:max_intents]
        if not intents:
            return "noop", None
        return "intents", intents
    if open_intents_empty:
        raise ValueError("intents is required when open_intents is empty")
    return "noop", None


def validate_bootstrap_execute_payload(
    payload: dict[str, Any],
) -> tuple[str, dict[str, str] | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_execute_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")

    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")

    result = {"fact_description": fact_description.strip()}
    complete = data.get("complete")
    if complete is None:
        raise ValueError("complete is required")
    if not isinstance(complete, dict):
        raise ValueError("complete must be an object")
    complete_description = complete.get("description")
    if not isinstance(complete_description, str) or not complete_description.strip():
        raise ValueError("complete.description is required")
    result["complete_description"] = complete_description.strip()
    return "complete", result


def validate_bootstrap_conclude_payload(payload: dict[str, Any]) -> tuple[str, str | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_bootstrap_conclude_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    extra_keys = set(data) - {"fact", "complete"}
    if extra_keys:
        raise ValueError("unexpected keys in conclude payload")
    fact = data.get("fact")
    if not isinstance(fact, dict):
        raise ValueError("fact is required")
    fact_description = fact.get("description")
    if not isinstance(fact_description, str) or not fact_description.strip():
        raise ValueError("fact.description is required")
    return "fact", fact_description.strip()


def validate_explore_payload(payload: dict[str, Any]) -> tuple[str, str | None]:
    accepted, data = _unwrap_wrapped_payload(payload)
    if accepted is False:
        return "rejected", None
    if accepted is None:
        if not _looks_like_explore_data(payload):
            raise ValueError("accepted must be true or false")
        data = payload
    if not isinstance(data, dict):
        raise ValueError("accepted must be true or false")
    description = data.get("description")
    if not isinstance(description, str) or not description.strip():
        raise ValueError("description is required")
    return "fact", description.strip()


# --- Pydantic models + JSON schemas (for response_format) --------------------


class CompletePayload(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    from_: list[str] = Field(alias="from", min_length=1)
    description: str


class IntentPayload(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    from_: list[str] = Field(alias="from", min_length=1)
    description: str


class ReasonOutput(BaseModel):
    """One of: completion, new intents, or a no-op (all optional)."""

    complete: CompletePayload | None = None
    intents: list[IntentPayload] | None = None


class FactPayload(BaseModel):
    description: str


class BootstrapOutput(BaseModel):
    fact: FactPayload
    complete: FactPayload | None = None


class ExploreOutput(BaseModel):
    description: str


JSON_SCHEMA_CAIRN_REASON: dict[str, Any] = ReasonOutput.model_json_schema()
JSON_SCHEMA_CAIRN_BOOTSTRAP: dict[str, Any] = BootstrapOutput.model_json_schema()
JSON_SCHEMA_CAIRN_EXPLORE: dict[str, Any] = ExploreOutput.model_json_schema()


__all__ = [
    "JSON_SCHEMA_CAIRN_BOOTSTRAP",
    "JSON_SCHEMA_CAIRN_EXPLORE",
    "JSON_SCHEMA_CAIRN_REASON",
    "BootstrapOutput",
    "ExploreOutput",
    "ReasonOutput",
    "parse_json_output",
    "validate_bootstrap_conclude_payload",
    "validate_bootstrap_execute_payload",
    "validate_explore_payload",
    "validate_reason_payload",
]
