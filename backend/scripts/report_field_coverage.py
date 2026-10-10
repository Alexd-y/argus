#!/usr/bin/env python3
"""Report field-coverage inventory (spec "Как проверять" / RC-13).

Every field of every ``ReportDocumentV1`` model must be rendered in all three readable
formats (Markdown / XML / HTML) unless it is explicitly marked
``Field(json_schema_extra={"render": "json_only"})`` — the allow-list of deliberately
JSON-only fields. This prints one line per field missing from a readable format and
exits non-zero if any remain; the regression test
``tests/unit/reports/test_report_field_coverage.py`` asserts the output is empty.

Run from the repo root::

    python backend/scripts/report_field_coverage.py

The field name is matched as a whole word in each renderer's *source* — a coarse net
(a field whose name collides with unrelated tokens reads as covered); the exhaustive
value-level check is ``content_parity_blockers(..., doc=doc)`` exercised by
``tests/unit/reports/test_render_parity_full_document.py``.
"""

from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

_BACKEND = Path(__file__).resolve().parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from src.reports import report_document as rd  # noqa: E402

_RENDERERS = ("markdown_renderer", "xml_renderer", "html_renderer")


def _renderer_sources() -> dict[str, str]:
    base = _BACKEND / "src" / "reports" / "renderers"
    return {name: (base / f"{name}.py").read_text(encoding="utf-8") for name in _RENDERERS}


def missing_fields() -> list[str]:
    """Return ``"Model.field: NOT in <renderers>"`` for every ``render="all"`` field whose
    name does not appear in one or more readable renderers (empty == full coverage)."""
    sources = _renderer_sources()
    out: list[str] = []
    for _name, model in inspect.getmembers(rd, inspect.isclass):
        if model.__module__ != rd.__name__ or not hasattr(model, "model_fields"):
            continue
        for field_name in model.model_fields:
            if rd.field_render_policy(model, field_name) != rd.RENDER_POLICY_ALL:
                continue  # allow-listed (json_only) — absence is a decision, not a gap
            pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(field_name)}(?![A-Za-z0-9_])")
            missing = [name for name, text in sources.items() if not pattern.search(text)]
            if missing:
                out.append(f"{model.__name__}.{field_name}: NOT in {', '.join(missing)}")
    return out


def main() -> int:
    rows = missing_fields()
    for row in rows:
        print(row)
    print(f"--- {len(rows)} field(s) not rendered in every readable format ---", file=sys.stderr)
    return 1 if rows else 0


if __name__ == "__main__":
    raise SystemExit(main())
