"""Part III Phase V — PDF backend selection: WeasyPrint default, Chromium opt-in."""

from __future__ import annotations

import src.reports.pdf_backend as pdf_backend
from src.reports.pdf_backend import (
    ChromiumBackend,
    DisabledBackend,
    get_active_backend,
    list_backend_names,
)


def test_chromium_registered_but_not_in_fallback_chain():
    # Selectable by explicit env, never chosen automatically (browser in prod is opt-in).
    assert "chromium" in pdf_backend._BACKEND_REGISTRY
    assert "chromium" not in list_backend_names()


def test_chromium_is_protocol_compliant():
    assert ChromiumBackend.name == "chromium"
    assert hasattr(ChromiumBackend, "is_available")
    assert hasattr(ChromiumBackend, "render")


def test_explicit_chromium_env_selects_or_falls_back(monkeypatch):
    monkeypatch.setenv("REPORT_PDF_BACKEND", "chromium")
    backend = get_active_backend()
    # If a browser is installed → chromium; otherwise graceful fallback down the chain.
    assert backend.name in {"chromium", "weasyprint", "latex", "disabled"}


def test_unavailable_chromium_render_returns_false(monkeypatch, tmp_path):
    # Force "no playwright" so render fails gracefully (never raises).
    monkeypatch.setattr(ChromiumBackend, "is_available", staticmethod(lambda: False))
    out = tmp_path / "r.pdf"
    ok = ChromiumBackend().render(
        html_content="<html><body>x</body></html>",
        output_path=out,
        scan_completed_at="2026-01-01T00:00:00Z",
    )
    assert ok is False


def test_disabled_backend_always_available():
    assert DisabledBackend.is_available() is True
