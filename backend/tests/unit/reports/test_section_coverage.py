"""Wave 4 / Stage 2 — one canonical section registry, honoured by all four formats.

The registry (:mod:`src.reports.section_registry`) is the single source of section
order + presence for the canonical renderers. These prove every renderer now walks it
and reports an explicit status for every section (no silent omission), and that the
VALHALLA_REQUIRED_SOURCES → registry bridge (VP-04) has no drift.
"""

from __future__ import annotations

import json as _json
from html import escape as _esc

from src.reports.renderers.html_renderer import render_html
from src.reports.renderers.json_renderer import render_json
from src.reports.renderers.markdown_renderer import render_markdown
from src.reports.renderers.xml_renderer import render_xml
from src.reports.report_document import ReportDocumentV1
from src.reports.section_registry import SECTION_ORDER, iter_sections, section_ids
from src.reports.valhalla_completeness import (
    REQUIRED_SOURCE_TO_REGISTRY_SECTIONS,
    required_source_sections,
)


def _empty_doc() -> ReportDocumentV1:
    return ReportDocumentV1(scan_id="s", tenant_id="t", target="http://x").finalized()


def test_json_carries_every_registry_section() -> None:
    doc = _empty_doc()
    payload = _json.loads(render_json(doc))
    cov = {row["section_id"] for row in payload["section_coverage"]}
    assert cov == set(section_ids())
    # An empty doc: data-bearing sections report their declared empty_status.
    by_id = {row["section_id"]: row for row in payload["section_coverage"]}
    assert by_id["findings"]["present"] is False
    assert by_id["findings"]["status"] == "no_findings"
    assert by_id["passport"]["present"] is True


def test_readable_formats_list_every_section_title() -> None:
    doc = _empty_doc()
    md, xml, html = render_markdown(doc), render_xml(doc), render_html(doc)
    for spec in SECTION_ORDER:
        # Markdown carries the raw title; XML/HTML escape markup-significant chars (``&``).
        assert spec.title in md, f"{spec.section_id} title missing from markdown"
        assert _esc(spec.title) in html, f"{spec.section_id} title missing from html"
        assert _esc(spec.title) in xml, f"{spec.section_id} title missing from xml"


def test_xml_section_coverage_has_status_per_section() -> None:
    doc = _empty_doc()
    xml = render_xml(doc)
    assert "<section_coverage>" in xml
    assert 'status="no_findings"' in xml  # findings section empty on an empty doc


def test_md_and_html_both_have_section_coverage_header() -> None:
    # C-28 MD↔HTML section-header set equality must stay balanced.
    doc = _empty_doc()
    assert "## Section Coverage" in render_markdown(doc)
    assert "<h2>Section Coverage</h2>" in render_html(doc)


def test_required_source_registry_bridge_has_no_drift() -> None:
    # Every RequiredSource.section must be mapped (possibly to ()), and every mapped
    # registry id must be a real section (R-6.3 vocabulary unification).
    valid_ids = set(section_ids())
    mapped = set(REQUIRED_SOURCE_TO_REGISTRY_SECTIONS)
    missing = required_source_sections() - mapped
    assert not missing, f"unmapped RequiredSource.section(s): {missing}"
    for src_section, reg_ids in REQUIRED_SOURCE_TO_REGISTRY_SECTIONS.items():
        for rid in reg_ids:
            assert rid in valid_ids, f"{src_section} maps to unknown registry id {rid}"


def test_iter_sections_is_stable_and_complete() -> None:
    doc = _empty_doc()
    states = iter_sections(doc)
    assert [s.section_id for s in states] == list(section_ids())
    assert all(s.status for s in states)  # never an empty status string
