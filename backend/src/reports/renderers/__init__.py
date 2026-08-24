"""Canonical report renderers — every format derives from ReportDocumentV1.

The four renderers below (JSON / Markdown / XML / HTML→PDF) are guaranteed to be
semantically equivalent because they all read the exact same immutable snapshot
(Requirements R7.3 / P4). Parity is verified in
``tests/unit/reports/test_report_snapshot_parity.py``.
"""

from __future__ import annotations

from src.reports.renderers.html_renderer import render_html
from src.reports.renderers.json_renderer import render_json
from src.reports.renderers.markdown_renderer import render_markdown
from src.reports.renderers.xml_renderer import render_xml

#: format id -> (mime, renderer)
CANONICAL_RENDERERS = {
    "json": ("application/json", render_json),
    "md": ("text/markdown", render_markdown),
    "xml": ("application/xml", render_xml),
    "html": ("text/html", render_html),
}

__all__ = [
    "CANONICAL_RENDERERS",
    "render_html",
    "render_json",
    "render_markdown",
    "render_xml",
]
