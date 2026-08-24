"""JSON renderer — the canonical serialization of the snapshot."""

from __future__ import annotations

import json

from src.reports.report_document import ReportDocumentV1


def render_json(doc: ReportDocumentV1, *, indent: int | None = 2) -> str:
    """Serialize the full snapshot to JSON (lossless)."""
    return json.dumps(doc.model_dump(mode="json"), indent=indent, sort_keys=True, ensure_ascii=False)


__all__ = ["render_json"]
