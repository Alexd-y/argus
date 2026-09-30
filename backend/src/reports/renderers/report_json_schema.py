"""Valhalla report JSON: schema validation (formats prompt Phase 3).

Validates a rendered canonical JSON document against the versioned schema file
``backend/config/schemas/valhalla_report_v2.schema.json`` using ``jsonschema``.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

#: Path to the versioned JSON Schema (single source of truth; not an inline string).
JSON_SCHEMA_PATH: Path = (
    Path(__file__).resolve().parents[3] / "config" / "schemas" / "valhalla_report_v2.schema.json"
)


@lru_cache(maxsize=1)
def _load_schema() -> dict:
    with JSON_SCHEMA_PATH.open("rb") as fh:
        return json.load(fh)


def validate_valhalla_report_json(json_text: str) -> list[str]:
    """Return schema validation errors for ``json_text`` (empty list == valid)."""
    from jsonschema import Draft202012Validator  # noqa: PLC0415 — optional heavy dep

    try:
        data = json.loads(json_text)
    except (ValueError, TypeError) as exc:
        return [f"json_parse_error: {exc}"]
    validator = Draft202012Validator(_load_schema())
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    return [f"{list(e.path)}: {e.message}" for e in errors]


__all__ = ["JSON_SCHEMA_PATH", "validate_valhalla_report_json"]
