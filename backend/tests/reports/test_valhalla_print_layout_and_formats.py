"""Phase A–H regression tests for the empty-single-page Valhalla PDF defect.

Covers the concrete Part-I fixes:
    * D1 — print CSS no longer leaves unfragmentable flex/100vh/sticky on content
      containers (``test_print_css_has_no_unfragmentable_flex``);
    * D5 — XML is real XML, not CSV; the pipeline knows the ``xml`` format
      (``test_report_pipeline_registers_xml``, ``test_download_report_xml_branch_explicit``);
    * unknown formats return HTTP 400 instead of a silent CSV substitution
      (``test_download_report_rejects_unknown_format``);
    * D4 — ``valhalla_release_blockers`` is wired into the prod pipeline
      (``test_release_blockers_wired_into_pipeline``,
      ``test_compute_valhalla_release_blockers_flags_llm_and_tier``).

All tests are static/unit — no Postgres, WeasyPrint or LLM required.
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

from src.reports import report_pipeline

_TEMPLATE = (
    Path(report_pipeline.__file__).resolve().parent
    / "templates"
    / "reports"
    / "valhalla_secreport_base.html.j2"
)


def _extract_media_print_block(css: str) -> str:
    """Return the body of the first ``@media print { ... }`` rule (brace-balanced)."""
    start = css.index("@media print")
    brace = css.index("{", start)
    depth = 0
    for i in range(brace, len(css)):
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
            if depth == 0:
                return css[brace + 1 : i]
    raise AssertionError("unbalanced @media print block")


def test_print_css_has_no_unfragmentable_flex() -> None:
    """D1 regression: the print context must not keep flex/100vh/sticky containers.

    WeasyPrint does not fragment flex/grid containers across pages; a content
    container that stays flex with ``min-height:100vh`` collapses the whole report
    onto one page. The ``@media print`` block must neutralise this.
    """
    css = _TEMPLATE.read_text(encoding="utf-8")
    print_block = _extract_media_print_block(css)
    # Strip CSS comments — we assert on declarations, not documentation.
    print_block = re.sub(r"/\*.*?\*/", "", print_block, flags=re.DOTALL)

    # No viewport-height on any container in print.
    assert "100vh" not in print_block
    # No sticky positioning in print.
    assert "position: sticky" not in print_block and "position:sticky" not in print_block
    # #app must be explicitly reset to a block box so it can paginate.
    normalized = re.sub(r"\s+", " ", print_block)
    assert "#app { display: block;" in normalized or "#app{display:block;" in normalized
    # The main container and form area must drop their flex sizing.
    assert ".main-container { display: block; flex: none;" in normalized
    assert "#form-area {" in normalized and "flex: none;" in normalized


def test_report_pipeline_registers_xml() -> None:
    """D5: the pipeline must know ``xml`` so a stored artifact exists (no regenerate→CSV)."""
    assert "xml" in report_pipeline.REPORT_FORMAT_SET
    assert "xml" in report_pipeline.DEFAULT_REPORT_FORMATS
    assert report_pipeline.CONTENT_TYPES.get("xml") == "application/xml; charset=utf-8"


def test_report_pipeline_generates_xml_branch() -> None:
    """The generation loop must have an explicit ``xml`` branch calling ``generate_xml``."""
    src = inspect.getsource(report_pipeline.run_generate_report_pipeline)
    assert 'elif fmt == "xml":' in src
    assert "generate_xml(report_data" in src


def test_download_report_xml_branch_explicit() -> None:
    """D5: ``download_report`` must serve real XML via ``generate_xml`` for ``fmt == 'xml'``."""
    from src.api.routers import reports as reports_router

    src = inspect.getsource(reports_router.download_report)
    assert 'elif fmt == "xml":' in src
    assert "generate_xml(report_data" in src
    # And CSV must be an explicit branch, not the catch-all default.
    assert 'elif fmt == "csv":' in src


def test_download_report_rejects_unknown_format() -> None:
    """Unknown/unsupported formats must raise HTTP 400, never a silent CSV substitution."""
    from src.api.routers import reports as reports_router

    src = inspect.getsource(reports_router.download_report)
    # The regenerate branch ends with an explicit 400 for unsupported formats.
    assert "Unsupported format" in src
    assert "status_code=400" in src


def test_release_blockers_wired_into_pipeline() -> None:
    """D4 regression: ``valhalla_release_blockers`` must be called from the prod path."""
    # Imported into the pipeline module.
    assert hasattr(report_pipeline, "valhalla_release_blockers")
    # The pipeline evaluates blockers before marking the release ready.
    pipeline_src = inspect.getsource(report_pipeline.run_generate_report_pipeline)
    assert "_compute_valhalla_release_blockers(" in pipeline_src
    # The helper actually delegates to the aggregator.
    helper_src = inspect.getsource(report_pipeline._compute_valhalla_release_blockers)
    assert "valhalla_release_blockers(" in helper_src


def test_compute_valhalla_release_blockers_flags_llm_and_tier() -> None:
    """The wired helper blocks on tier swap and incomplete mandatory LLM analysis."""

    class _StubReportData:
        findings: list = []

    # LLM not run + tier swap → at least the LLM blocker and the tier blocker.
    blockers = report_pipeline._compute_valhalla_release_blockers(
        report_data=_StubReportData(),
        template_context={},
        requested_tier="midgard",
        actual_tier="valhalla",
        valhalla_llm_status="not_run",
    )
    assert any("VP-01" in b for b in blockers), blockers
    assert any("LLM analysis not complete" in b for b in blockers), blockers

    # LLM "ready" (→ normalised to completed) + matching tier + no findings → releasable.
    ok = report_pipeline._compute_valhalla_release_blockers(
        report_data=_StubReportData(),
        template_context={},
        requested_tier="valhalla",
        actual_tier="valhalla",
        valhalla_llm_status="ready",
    )
    assert ok == [], ok
