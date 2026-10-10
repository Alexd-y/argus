"""Phase 5 — PDF in the bundle, branded-template degradation, print layout (RC-16..RC-18)."""

from __future__ import annotations

import contextlib
import re
import types
from pathlib import Path

import pytest
from src.reports import generators
from src.reports import report_pipeline as rp
from src.reports.report_document import build_report_document
from src.reports.snapshot_builder import build_snapshot_from_report_data

_CSS_DIR = Path(__file__).resolve().parents[3] / "templates" / "reports"
_TIERS = ("asgard", "midgard", "valhalla")


# --------------------------------------------------------------------------- RC-18
def test_branded_pdf_template_failure_recorded(monkeypatch):
    """A branded-template render failure records a ReportFailure in the jinja context."""
    monkeypatch.setattr(generators, "_resolve_pdfa_mode", lambda **_k: False)
    monkeypatch.setattr(generators, "_resolve_branded_pdf_template_path", lambda _t: Path("x.j2"))
    monkeypatch.setattr(generators, "_build_branded_pdf_context", lambda *_a, **_k: {})

    def _boom(*_a, **_k):
        raise RuntimeError("jinja kaboom")

    monkeypatch.setattr(generators, "_render_branded_pdf_html", _boom)
    monkeypatch.setattr(generators, "generate_html", lambda *_a, **_k: b"<html/>")

    data = types.SimpleNamespace(report_id="r1", tenant_id="t1")
    ctx: dict = {}
    # generate_pdf records the degradation before it reaches the PDF backend; the backend
    # may then raise (unavailable) or succeed — either way the recording is what we assert.
    with contextlib.suppress(Exception):
        generators.generate_pdf(data, jinja_context=ctx, tier="valhalla")
    failures = ctx.get("render_failures") or []
    assert any(f["where"] == "branded_pdf_template" for f in failures), ctx


def test_render_failures_reach_snapshot_failures():
    """RC-18 propagation: a recorded render failure surfaces in doc.failures."""
    report_data = types.SimpleNamespace(findings=[], evidence=[], target="https://t")
    doc = build_snapshot_from_report_data(
        report_data,
        scan_meta={
            "failures": [
                {
                    "where": "branded_pdf_template",
                    "reason_code": "template_render_failed",
                    "message": "m",
                }
            ]
        },
    )
    assert any(f.where == "branded_pdf_template" for f in doc.failures)


# --------------------------------------------------------------------------- RC-17
def test_missing_pdf_raises_release_blocker(monkeypatch):
    """A Valhalla release with no PDF must be flagged, not shipped silently."""
    monkeypatch.setattr(rp, "generate_markdown", lambda *a, **k: b"# r\n")
    doc = build_report_document(scan_id="s", tenant_id="t", target="https://t")
    monkeypatch.setattr(rp, "build_snapshot_from_report_data", lambda *a, **k: doc)
    report_data = types.SimpleNamespace(findings=[], target="https://t", created_at=None)
    blockers = rp._compute_valhalla_release_blockers(
        report_data=report_data,
        template_context={},
        requested_tier="valhalla",
        actual_tier="valhalla",
        valhalla_llm_status="ready",
        pdf_missing=True,
    )
    assert any("PDF" in b for b in blockers), blockers


def test_pdf_present_no_blocker(monkeypatch):
    monkeypatch.setattr(rp, "generate_markdown", lambda *a, **k: b"# r\n")
    doc = build_report_document(scan_id="s", tenant_id="t", target="https://t")
    monkeypatch.setattr(rp, "build_snapshot_from_report_data", lambda *a, **k: doc)
    report_data = types.SimpleNamespace(findings=[], target="https://t", created_at=None)
    blockers = rp._compute_valhalla_release_blockers(
        report_data=report_data,
        template_context={},
        requested_tier="valhalla",
        actual_tier="valhalla",
        valhalla_llm_status="ready",
        pdf_missing=False,
    )
    assert not any("no PDF" in b for b in blockers), blockers


# --------------------------------------------------------------------------- RC-16
@pytest.mark.weasyprint_pdf
def test_roadmap_last_card_survives_pagination():
    """Acceptance #5 — a 30+ card roadmap must not be clipped after the first page.

    Renders the Valhalla print stylesheet around a long ``.roadmap-grid`` and asserts the
    LAST card's text appears in the PDF. Skips where WeasyPrint / a PDF text extractor is
    unavailable (the structural ``@media print`` guard above runs everywhere).
    """
    import io
    import os

    if os.environ.get("ARGUS_SKIP_WEASYPRINT_PDF"):
        pytest.skip("ARGUS_SKIP_WEASYPRINT_PDF set")
    try:
        import weasyprint  # noqa: PLC0415
    except Exception:  # noqa: BLE001 — import raises OSError when native libs are absent
        pytest.skip("WeasyPrint unavailable")
    try:
        import pypdf  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        pytest.skip("pypdf unavailable")

    css = (_CSS_DIR / "valhalla" / "pdf_styles.css").read_text(encoding="utf-8")
    cards = "".join(
        f'<div class="roadmap-card"><div class="phase-header">P{i}</div>'
        f"ROADMAPCARD{i:02d}</div>"
        for i in range(35)
    )
    html = (
        f"<html><head><style>{css}</style></head><body>"
        f'<div class="roadmap"><div class="roadmap-grid">{cards}</div></div>'
        f"</body></html>"
    )
    try:
        pdf_bytes = weasyprint.HTML(string=html).write_pdf()
    except Exception:  # noqa: BLE001 — native libs missing on host
        pytest.skip("WeasyPrint native libraries unavailable")
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    text = "".join(page.extract_text() or "" for page in reader.pages)
    assert len(reader.pages) >= 2, "roadmap should span multiple pages"
    assert "ROADMAPCARD34" in text.replace(" ", ""), "last roadmap card was clipped"


@pytest.mark.parametrize("tier", _TIERS)
def test_pdf_styles_have_print_block_for_variable_containers(tier):
    css = (_CSS_DIR / tier / "pdf_styles.css").read_text(encoding="utf-8")
    assert "@media print" in css, f"{tier}: no @media print block"
    # Strip comments, then find the print block body.
    stripped = re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)
    m = re.search(r"@media\s+print\s*\{(.*)\}\s*$", stripped, flags=re.DOTALL)
    assert m, f"{tier}: unparseable @media print block"
    print_block = m.group(1)
    # Variable-length grid containers must collapse to block so WeasyPrint paginates them.
    for selector in (".roadmap-grid", ".meta-grid"):
        if selector in css:
            assert selector in print_block, f"{tier}: {selector} not reset in @media print"
            idx = print_block.index(selector)
            segment = print_block[idx : idx + 200].replace(" ", "")
            assert "display:block" in segment, (
                f"{tier}: {selector} not set to display:block in print"
            )
