"""JSON renderer — the canonical serialization of the snapshot."""

from __future__ import annotations

import json

from src.reports.report_document import ReportDocumentV1

#: Public URN of the JSON contract (the versioned file is config/schemas/…schema.json).
VALHALLA_REPORT_JSON_SCHEMA_ID = "urn:argus:valhalla-report:v2:json"


def render_json(doc: ReportDocumentV1, *, indent: int | None = 2) -> str:
    """Serialize the full snapshot to JSON (lossless, deterministic).

    Carries a ``$schema`` reference so the document self-identifies against the
    published contract. Keys are sorted so ``render_json`` is byte-stable for a given
    snapshot (the basis of reproducible artifact hashes).
    """
    payload = doc.model_dump(mode="json")
    payload["$schema"] = VALHALLA_REPORT_JSON_SCHEMA_ID
    return json.dumps(payload, indent=indent, sort_keys=True, ensure_ascii=False)


__all__ = ["VALHALLA_REPORT_JSON_SCHEMA_ID", "render_json"]
