"""VH-LLM-10: PDF projection + visual/layout QA.

Full PDF rendering needs WeasyPrint's native libs (pango/cairo); when those are
unavailable the render test is skipped rather than silently passing. The
content-level QA (no mandatory block clipped/dropped) runs without a rasteriser.
"""

import pytest
from src.reports.llm_remediation.pdf import (
    PdfRenderUnavailableError,
    pdf_visual_qa,
    render_pdf,
)


def test_qa_content_has_no_missing_blocks(complete_document):
    result = pdf_visual_qa(complete_document, require_pdf=False)
    assert result.missing_blocks == []
    assert result.ok
    # Raster QA is honestly reported as not performed.
    assert result.raster_checked is False
    assert any("raster_qa_unavailable" in n for n in result.notes)


def test_render_pdf_when_weasyprint_functional(complete_document):
    try:
        pdf_bytes = render_pdf(complete_document)
    except PdfRenderUnavailableError:
        pytest.skip("WeasyPrint not installed")
    except OSError as exc:  # native libs (pango/cairo/gobject) missing on this host
        pytest.skip(f"WeasyPrint native libraries unavailable: {exc}")
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 500
