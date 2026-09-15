"""VH-LLM-10: PDF projection + visual/layout QA.

Full PDF rendering needs WeasyPrint's native libs (pango/cairo); when those are
unavailable the render test is skipped rather than silently passing. The
content-level QA (no mandatory block clipped/dropped) runs without a rasteriser.
"""

import io

import pytest
from PIL import Image, ImageDraw
from src.reports.llm_remediation.pdf import (
    RASTER_AVAILABLE,
    PdfRenderUnavailableError,
    pdf_visual_qa,
    raster_pdf_qa,
    render_pdf,
)


def _pdf_from_image(draw_fn) -> bytes:
    """Build a single-page PDF from a PIL image (no WeasyPrint needed)."""
    img = Image.new("RGB", (200, 200), "white")
    draw_fn(ImageDraw.Draw(img))
    buf = io.BytesIO()
    img.save(buf, format="PDF", resolution=72.0)
    return buf.getvalue()


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


@pytest.mark.skipif(not RASTER_AVAILABLE, reason="pypdfium2 + Pillow required")
def test_raster_qa_detects_content_page():
    pdf = _pdf_from_image(lambda d: d.rectangle([40, 40, 160, 160], fill="black"))
    result = raster_pdf_qa(pdf)
    assert result.page_count == 1
    assert result.blank_pages == []
    assert result.ok


@pytest.mark.skipif(not RASTER_AVAILABLE, reason="pypdfium2 + Pillow required")
def test_raster_qa_flags_blank_page():
    pdf = _pdf_from_image(lambda d: None)  # all-white page
    result = raster_pdf_qa(pdf)
    assert result.page_count == 1
    assert result.blank_pages == [0]
    assert not result.ok


@pytest.mark.skipif(not RASTER_AVAILABLE, reason="pypdfium2 + Pillow required")
def test_raster_qa_flags_edge_clipping():
    # A thick black band along the right edge simulates clipped content.
    pdf = _pdf_from_image(lambda d: d.rectangle([190, 0, 199, 199], fill="black"))
    result = raster_pdf_qa(pdf)
    assert 0 in result.edge_clip_pages
    assert not result.ok
