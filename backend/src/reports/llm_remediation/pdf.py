"""PDF projection + visual QA for the Valhalla LLM document (VH-LLM-08/10).

PDF is produced from the *same* HTML content set as :func:`render_html` — print
CSS only changes layout, never facts (prompt §11 "PDF и HTML"). WeasyPrint is
an optional/heavy dependency, imported at module top behind a guard so the rest
of the package stays import-safe when it is absent.

QA (prompt §13 L19): validates that every mandatory block survives into the
rendered document — no finding, remediation plan or closure conclusion may be
clipped or dropped. Full raster/pixel QA needs a PDF rasteriser (pypdfium2 /
pdf2image) which is not installed here; :func:`pdf_visual_qa` reports that gap
explicitly instead of silently passing.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.reports.llm_remediation.document import ValhallaLlmDocument
from src.reports.llm_remediation.render import render_html

try:  # pragma: no cover - availability depends on environment
    from weasyprint import HTML as _WeasyHTML
except Exception:  # pragma: no cover - weasyprint pulls native libs (pango/cairo)
    _WeasyHTML = None

try:  # pragma: no cover - optional rasteriser (pure-wheel, bundles pdfium)
    import pypdfium2 as _pdfium
except Exception:  # pragma: no cover
    _pdfium = None

try:  # pragma: no cover - Pillow for pixel inspection
    from PIL import Image as _PILImage
except Exception:  # pragma: no cover
    _PILImage = None

PDF_AVAILABLE = _WeasyHTML is not None
RASTER_AVAILABLE = _pdfium is not None and _PILImage is not None

#: A page whose darkest pixel is lighter than this is considered blank.
_BLANK_LUMA_THRESHOLD = 250
#: Dark pixels inside the outermost edge strip suggest content clipped at the
#: page boundary.
_EDGE_STRIP_PX = 2
_EDGE_DARK_LUMA = 90

_PRINT_CSS = """
@page { size: A4; margin: 18mm 15mm; @bottom-center { content: counter(page); } }
body { font-family: 'DejaVu Sans', sans-serif; font-size: 10pt; line-height: 1.4; }
section.finding { break-inside: avoid-page; margin-bottom: 8pt; }
h3 { break-after: avoid-page; }
.kv .k { font-weight: bold; }
""".strip()


class PdfRenderUnavailableError(RuntimeError):
    """Raised when a PDF is requested but WeasyPrint is not installed."""


def render_pdf(doc: ValhallaLlmDocument) -> bytes:
    """Render the document to PDF bytes from the shared HTML content set."""

    if _WeasyHTML is None:
        raise PdfRenderUnavailableError(
            "WeasyPrint is not available; cannot render the Valhalla PDF artifact"
        )
    html = render_html(doc)
    styled = html.replace("</head>", f"<style>{_PRINT_CSS}</style></head>", 1)
    return _WeasyHTML(string=styled).write_pdf()


@dataclass
class RasterQaResult:
    """Outcome of pixel-level rasterisation QA."""

    ok: bool
    page_count: int = 0
    blank_pages: list[int] = field(default_factory=list)
    edge_clip_pages: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def raster_pdf_qa(pdf_bytes: bytes, *, scale: float = 1.5) -> RasterQaResult:
    """Rasterise every PDF page and flag blank pages / edge clipping.

    Uses pypdfium2 (bundled pdfium) + Pillow. Each page is rendered to a bitmap;
    a page with no dark pixels is flagged blank, and dark pixels inside the
    outermost edge strip are flagged as potential content clipping (prompt L19).
    """

    if _pdfium is None or _PILImage is None:
        return RasterQaResult(ok=False, notes=["raster_dependencies_unavailable"])

    pdf = _pdfium.PdfDocument(pdf_bytes)
    blank: list[int] = []
    edge_clip: list[int] = []
    try:
        page_count = len(pdf)
        for index in range(page_count):
            page = pdf[index]
            bitmap = page.render(scale=scale)
            image = bitmap.to_pil().convert("L")
            width, height = image.size
            low, _high = image.getextrema()
            if low >= _BLANK_LUMA_THRESHOLD:
                blank.append(index)
            if _edge_has_dark_pixels(image, width, height):
                edge_clip.append(index)
    finally:
        pdf.close()

    return RasterQaResult(
        ok=not blank and not edge_clip and page_count > 0,
        page_count=page_count,
        blank_pages=blank,
        edge_clip_pages=edge_clip,
    )


def _edge_has_dark_pixels(image: object, width: int, height: int) -> bool:
    """Return True if the outermost edge strips contain dark (content) pixels."""

    strip = _EDGE_STRIP_PX
    # Right and bottom strips are the usual clipping zones for overflowing cards.
    right = image.crop((max(0, width - strip), 0, width, height))
    bottom = image.crop((0, max(0, height - strip), width, height))
    return any(region.getextrema()[0] < _EDGE_DARK_LUMA for region in (right, bottom))


@dataclass
class PdfQaResult:
    """Outcome of the PDF/layout QA pass."""

    ok: bool
    page_count: int = 0
    missing_blocks: list[str] = field(default_factory=list)
    raster_checked: bool = False
    blank_pages: list[int] = field(default_factory=list)
    edge_clip_pages: list[int] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def pdf_visual_qa(doc: ValhallaLlmDocument, *, require_pdf: bool = True) -> PdfQaResult:
    """Verify no mandatory block is clipped/dropped in the rendered document.

    Checks that every finding id and both LLM blocks appear in the HTML content
    set that drives the PDF, and renders the PDF to confirm a non-empty,
    multi-page document. Pixel-level raster QA is reported as not performed when
    no rasteriser is installed.
    """

    html = render_html(doc)
    missing: list[str] = []
    for node in doc.findings:
        if node.finding_id not in html:
            missing.append(f"finding:{node.finding_id}")
        if node.remediation is not None and "LLM-план устранения" not in html:
            missing.append("block:remediation-heading")
        if node.closure is not None and "LLM-вывод по закрытию" not in html:
            missing.append("block:closure-heading")
    if "Итоговые выводы по устранению и закрытию" not in html:
        missing.append("section:summary")

    notes: list[str] = []
    page_count = 0
    raster_checked = False
    blank_pages: list[int] = []
    edge_clip_pages: list[int] = []

    if require_pdf:
        if _WeasyHTML is None:
            return PdfQaResult(
                ok=False,
                missing_blocks=missing,
                notes=["weasyprint_unavailable"],
            )
        document = _WeasyHTML(string=render_html(doc)).render()
        page_count = len(document.pages)
        pdf_bytes = document.write_pdf()
        if not pdf_bytes.startswith(b"%PDF"):
            missing.append("pdf:invalid_header")

        if RASTER_AVAILABLE:
            raster = raster_pdf_qa(pdf_bytes)
            raster_checked = True
            blank_pages = raster.blank_pages
            edge_clip_pages = raster.edge_clip_pages
            if blank_pages:
                missing.append(f"raster:blank_pages:{blank_pages}")
            if edge_clip_pages:
                missing.append(f"raster:edge_clip_pages:{edge_clip_pages}")
        else:
            notes.append("raster_qa_unavailable: install pypdfium2 + Pillow for pixel checks")
    else:
        notes.append("raster_qa_unavailable: install pypdfium2 + Pillow for pixel checks")

    return PdfQaResult(
        ok=not missing and (page_count > 0 or not require_pdf),
        page_count=page_count,
        missing_blocks=missing,
        raster_checked=raster_checked,
        blank_pages=blank_pages,
        edge_clip_pages=edge_clip_pages,
        notes=notes,
    )


__all__ = [
    "PDF_AVAILABLE",
    "RASTER_AVAILABLE",
    "PdfQaResult",
    "PdfRenderUnavailableError",
    "RasterQaResult",
    "pdf_visual_qa",
    "raster_pdf_qa",
    "render_pdf",
]
