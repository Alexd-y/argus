"""Phase 2/3 — every ReportDocumentV1 field is rendered in every readable format.

Runs the `backend/scripts/report_field_coverage.py` inventory and asserts it finds
nothing: every ``render="all"`` field appears (by name) in Markdown, XML and HTML. A
new uncovered field fails this test. JSON-only fields (the allow-list) are excluded by
the script via ``field_render_policy``.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_coverage_module():
    script = Path(__file__).resolve().parents[3] / "scripts" / "report_field_coverage.py"
    spec = importlib.util.spec_from_file_location("report_field_coverage", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_field_rendered_in_every_readable_format():
    rows = _load_coverage_module().missing_fields()
    assert rows == [], "fields missing from a readable renderer:\n" + "\n".join(rows)
