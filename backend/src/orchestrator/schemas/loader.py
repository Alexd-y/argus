"""Loader and validator for the ValidationPlanV1 LLM output contract.

Two surfaces:
  1. :func:`load_validation_plan_v1_schema` — returns the raw JSON Schema dict.
     Cached on first call; the file is shipped alongside the module.
  2. :func:`validate_validation_plan` — validates an arbitrary payload against the
     schema AND parses it into the Pydantic :class:`ValidationPlanV1` model. Raises
     :class:`ValidationPlanError` (with a human-readable JSON-pointer-like path) on
     failure; returns the parsed Pydantic model on success.

The Pydantic mirror exists so call sites get strict typed access (IDE + mypy)
without having to ``dict.get`` their way through the LLM response. Both surfaces
share a single source of truth (the JSON Schema file) — the Pydantic model is
constructed from values that have already been schema-validated, so it never
permits more than the schema allows.
"""

from __future__ import annotations

import json
from enum import StrEnum
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictStr,
    field_validator,
)

SCHEMA_ID: Final[str] = "https://schemas.argus.local/validation_plan_v1.json"
_SCHEMA_FILENAME: Final[str] = "validation_plan_v1.json"


class ValidationPlanError(ValueError):
    """Raised when a payload fails ValidationPlanV1 schema validation.

    Attributes
    ----------
    field_path : str
        JSON-pointer-like path to the offending field (e.g. ``payload_strategy.raw_payloads_allowed``).
    reason : str
        Human-readable reason from the validator.
    """

    def __init__(self, field_path: str, reason: str) -> None:
        self.field_path = field_path
        self.reason = reason
        super().__init__(
            f"ValidationPlanV1 validation failed at {field_path!r}: {reason}"
        )


class MutationClass(StrEnum):
    """Allowed payload mutation strategies (Backlog/dev1_md §5/§6)."""

    CANONICALIZATION = "canonicalization"
    CONTEXT_ENCODING = "context_encoding"
    LENGTH_VARIATION = "length_variation"
    CASE_NORMALIZATION = "case_normalization"
    CHARSET_SHIFT = "charset_shift"
    WAF_DETOUR_LITE = "waf_detour_lite"


class ValidatorTool(StrEnum):
    """Allowed validator tool kinds (Backlog/dev1_md §6)."""

    SAFE_VALIDATOR = "safe_validator"
    BROWSER_VALIDATOR = "browser_validator"
    OAST_CANARY = "oast_canary"
    PAYLOAD_REGISTRY = "payload_registry"


class RiskRating(StrEnum):
    """LLM-emitted risk rating (Backlog/dev1_md §6)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class PayloadStrategyV1(BaseModel):
    """``payload_strategy`` block of ValidationPlanV1.

    ``raw_payloads_allowed`` is locked to False at the schema level
    (``const: false``); the model mirrors the constraint so accidental
    construction with True fails fast.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    registry_family: StrictStr
    mutation_classes: list[MutationClass] = Field(default_factory=list)
    raw_payloads_allowed: StrictBool

    @field_validator("raw_payloads_allowed")
    @classmethod
    def _reject_raw_payloads(cls, value: bool) -> bool:
        if value is not False:
            raise ValueError("raw_payloads_allowed must be False (security guardrail)")
        return value


class ValidatorSpecV1(BaseModel):
    """``validator`` block of ValidationPlanV1."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    tool: ValidatorTool
    inputs: dict[str, Any] = Field(default_factory=dict)
    success_signals: list[StrictStr] = Field(default_factory=list)
    stop_conditions: list[StrictStr] = Field(default_factory=list)


class ValidationPlanV1(BaseModel):
    """Pydantic mirror of the ValidationPlanV1 JSON Schema (Backlog/dev1_md §6).

    Constructed via :func:`validate_validation_plan` after schema validation; manual
    construction is also supported for tests and Python-side callers.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis: StrictStr = Field(min_length=8, max_length=500)
    risk: RiskRating
    payload_strategy: PayloadStrategyV1
    validator: ValidatorSpecV1
    approval_required: StrictBool
    evidence_to_collect: list[StrictStr] = Field(default_factory=list)
    remediation_focus: list[StrictStr] = Field(default_factory=list)


def _schema_path() -> Path:
    return Path(__file__).resolve().parent / _SCHEMA_FILENAME


@lru_cache(maxsize=1)
def load_validation_plan_v1_schema() -> dict[str, Any]:
    """Load and cache the ValidationPlanV1 JSON Schema as a dict.

    The schema is checked against Draft 2020-12 meta-schema on first load; this
    catches typos before any payload validation happens.
    """
    raw = _schema_path().read_text(encoding="utf-8")
    schema: dict[str, Any] = json.loads(raw)
    Draft202012Validator.check_schema(schema)
    return schema


def _format_field_path(error: JsonSchemaValidationError) -> str:
    """Render a jsonschema error path as a dotted JSON-pointer-like string."""
    if not error.absolute_path:
        return "<root>"
    parts: list[str] = []
    for segment in error.absolute_path:
        if isinstance(segment, int):
            parts.append(f"[{segment}]")
        else:
            parts.append(str(segment))
    return ".".join(p.lstrip(".") for p in parts) or "<root>"


def _sanitize_pydantic_errors(exc: BaseException) -> str:
    """Render a Pydantic ``ValidationError`` as a payload-free string.

    Pydantic v2's default ``str(ValidationError)`` embeds ``input_value=...`` and
    ``input=...`` snippets that echo the rejected payload. That is unsafe to
    surface in API error responses (the orchestrator forwards
    ``ValidationPlanError.reason`` to clients), so we project each error down to
    ``{loc}: {msg} (type={type})`` and drop the ``input`` / ``ctx.input_value``
    keys entirely.

    Falls back to the exception class name when ``errors()`` is missing or
    raises (defense in depth — keeps the caller alive even on non-Pydantic
    exceptions that slip into this branch).
    """
    errors_fn = getattr(exc, "errors", None)
    if not callable(errors_fn):
        return type(exc).__name__
    try:
        items = errors_fn()
    except Exception:  # noqa: BLE001 - best-effort sanitization
        return type(exc).__name__
    if not items:
        return type(exc).__name__
    parts: list[str] = []
    for err in items:
        loc = err.get("loc", ()) or ()
        loc_path = ".".join(str(p) for p in loc) or "<root>"
        msg = str(err.get("msg", "")).strip() or "validation failed"
        err_type = str(err.get("type", "")).strip() or "unknown"
        parts.append(f"{loc_path}: {msg} (type={err_type})")
    return "; ".join(parts)


def validate_validation_plan(payload: dict[str, Any]) -> ValidationPlanV1:
    """Validate ``payload`` against ValidationPlanV1 and return a typed model.

    Raises
    ------
    ValidationPlanError
        On any schema or Pydantic validation failure. The raised
        ``ValidationPlanError`` exposes only field path, error type, and the
        Pydantic message — input values from the rejected payload are never
        echoed (the loader strips ``input`` / ``ctx.input_value`` from
        Pydantic's error structures before rendering).
    """
    schema = load_validation_plan_v1_schema()
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(payload), key=lambda e: list(e.absolute_path))
    if errors:
        first = errors[0]
        raise ValidationPlanError(
            field_path=_format_field_path(first),
            reason=first.message,
        )
    try:
        return ValidationPlanV1.model_validate(payload)
    except Exception as exc:  # noqa: BLE001 - convert to domain error
        loc = "<root>"
        errors_fn = getattr(exc, "errors", None)
        if callable(errors_fn):
            try:
                items = errors_fn()
                if items:
                    loc = (
                        ".".join(str(part) for part in items[0].get("loc", ()) or ())
                        or "<root>"
                    )
            except Exception:  # noqa: BLE001 - best-effort path extraction
                loc = "<root>"
        raise ValidationPlanError(
            field_path=loc,
            reason=_sanitize_pydantic_errors(exc),
        ) from exc
