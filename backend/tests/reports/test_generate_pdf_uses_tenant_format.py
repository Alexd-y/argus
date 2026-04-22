"""B6-T02 / T48 — ``generate_pdf`` must honour the per-tenant PDF archival flag.

Two layers:

1. **Pure-function unit tests** for ``_resolve_pdfa_mode`` exercising every
   cell of the precedence matrix:

       per-tenant value     |  REPORT_PDFA_MODE env  |  expected pdfa_mode
       ---------------------|------------------------|---------------------
       None                 |  unset / falsy         |  False
       None                 |  truthy                |  True
       "standard"           |  unset / falsy         |  False
       "standard"           |  truthy                |  False  + WARNING log
       "pdfa-2u"            |  unset / falsy         |  True
       "pdfa-2u"            |  truthy                |  True
       "pdfa-3u" (junk)     |  truthy                |  True   + WARNING log
       "pdfa-3u" (junk)     |  unset / falsy         |  False  + WARNING log

2. **Backend-integration smoke test** for ``generate_pdf`` proving the
   resolved boolean reaches ``backend.render(..., pdfa_mode=...)`` when the
   LatexBackend path is taken (the only backend that consumes the flag).
   We stub the LaTeX surface (``resolve_latex_template_path``,
   ``render_latex_template``, ``render_pdfa_xmpdata``,
   ``get_active_backend``) so the test runs without ``latexmk`` on the host.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

import src.reports.generators as gen_mod
import src.reports.pdf_backend as pdf_backend_mod
from src.api.schemas import ReportSummary
from src.reports.generators import ReportData


# ---------------------------------------------------------------------------
# Fixtures — sample ReportData + clean env per test.
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_report_data() -> ReportData:
    return ReportData(
        report_id="rpt-test-0001",
        target="https://example.test",
        summary=ReportSummary(
            critical=0,
            high=1,
            medium=0,
            low=0,
            info=0,
            technologies=["nginx"],
            sslIssues=0,
            headerIssues=0,
            leaksFound=False,
        ),
        findings=[],
        technologies=["nginx"],
        created_at="2026-04-22T00:00:00Z",
        tenant_id="tenant-test-0001",
    )


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make every test responsible for setting ``REPORT_PDFA_MODE``."""
    monkeypatch.delenv("REPORT_PDFA_MODE", raising=False)


# ---------------------------------------------------------------------------
# Layer 1 — _resolve_pdfa_mode pure-function precedence tests.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tenant_format, env_value, expected",
    [
        # No per-tenant override → env path applies
        (None, None, False),
        (None, "0", False),
        (None, "false", False),
        (None, "1", True),
        (None, "true", True),
        (None, "TRUE", True),
        (None, "yes", True),
        (None, "on", True),
        # Tenant explicitly opts into pdfa-2u → env ignored
        ("pdfa-2u", None, True),
        ("pdfa-2u", "0", True),
        ("pdfa-2u", "false", True),
        ("pdfa-2u", "1", True),
        # Tenant explicitly chooses standard → env ignored even when truthy
        ("standard", None, False),
        ("standard", "0", False),
        ("standard", "false", False),
        ("standard", "1", False),
        ("standard", "true", False),
    ],
)
def test_resolve_pdfa_mode_matrix(
    tenant_format: str | None,
    env_value: str | None,
    expected: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if env_value is None:
        monkeypatch.delenv("REPORT_PDFA_MODE", raising=False)
    else:
        monkeypatch.setenv("REPORT_PDFA_MODE", env_value)

    result = gen_mod._resolve_pdfa_mode(
        pdf_archival_format=tenant_format,
        report_id="rpt-1",
        tenant_id="tenant-1",
    )
    assert result is expected, (
        f"_resolve_pdfa_mode(pdf_archival_format={tenant_format!r}, "
        f"REPORT_PDFA_MODE={env_value!r}) returned {result!r}, "
        f"expected {expected!r}"
    )


def test_resolve_pdfa_mode_env_ignored_logs_warning_when_tenant_opts_out(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Tenant ``"standard"`` + ``REPORT_PDFA_MODE=1`` → False + warning."""
    monkeypatch.setenv("REPORT_PDFA_MODE", "1")
    caplog.set_level(logging.WARNING, logger=gen_mod.__name__)

    result = gen_mod._resolve_pdfa_mode(
        pdf_archival_format="standard",
        report_id="rpt-1",
        tenant_id="tenant-1",
    )
    assert result is False
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "pdfa_mode_env_ignored_per_tenant_override" in (r.message or "")
        for r in warnings
    ), (
        "expected warning 'pdfa_mode_env_ignored_per_tenant_override' to be "
        f"logged, got: {[r.message for r in warnings]}"
    )


def test_resolve_pdfa_mode_unknown_tenant_format_logs_warning_and_falls_back(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An unknown tenant value MUST never silently pick a side."""
    monkeypatch.setenv("REPORT_PDFA_MODE", "0")
    caplog.set_level(logging.WARNING, logger=gen_mod.__name__)

    result = gen_mod._resolve_pdfa_mode(
        pdf_archival_format="pdfa-3u",  # not in the closed taxonomy
        report_id="rpt-1",
        tenant_id="tenant-1",
    )
    assert result is False, "unknown format must fall back to env (which is 0 here)"
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert any(
        "pdfa_mode_unknown_tenant_format" in (r.message or "")
        for r in warnings
    ), (
        "expected warning 'pdfa_mode_unknown_tenant_format' to be logged, "
        f"got: {[r.message for r in warnings]}"
    )


# ---------------------------------------------------------------------------
# Layer 2 — generate_pdf integration with a stubbed LatexBackend.
# ---------------------------------------------------------------------------


@dataclass
class _RenderCall:
    pdfa_mode: bool
    has_xmpdata: bool
    latex_present: bool


class _FakeLatexBackend(pdf_backend_mod.LatexBackend):
    """LatexBackend stand-in that records args and synthesises a PDF blob."""

    name = "latex"

    def __init__(self) -> None:
        self.calls: list[_RenderCall] = []

    @staticmethod
    def is_available() -> bool:  # type: ignore[override]
        return True

    def render(  # type: ignore[override]
        self,
        *,
        html_content: str,
        output_path: Path,
        scan_completed_at: str,
        base_url: str,
        latex_template_content: str | None,
        pdfa_mode: bool,
        xmpdata_content: str | None,
    ) -> bool:
        self.calls.append(
            _RenderCall(
                pdfa_mode=pdfa_mode,
                has_xmpdata=xmpdata_content is not None,
                latex_present=latex_template_content is not None,
            )
        )
        # Synthesise a minimal PDF so generate_pdf returns successfully.
        output_path.write_bytes(b"%PDF-1.4\n%fake\n%%EOF\n")
        return True


@pytest.fixture
def stubbed_latex_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[_FakeLatexBackend]:
    """Force ``generate_pdf`` down the LatexBackend path with deterministic stubs."""
    fake_backend = _FakeLatexBackend()

    def _fake_get_active_backend() -> Any:
        return fake_backend

    def _fake_resolve_latex_template_path(_tier: str) -> Path:
        return Path("fake-template.tex.j2")

    def _fake_render_latex_template(_tier: str, _ctx: dict[str, Any]) -> str:
        return "\\documentclass{article}\\begin{document}stub\\end{document}"

    def _fake_render_pdfa_xmpdata(_tier: str, _ctx: dict[str, Any]) -> str:
        return "<x:xmpmeta/>"

    monkeypatch.setattr(
        pdf_backend_mod, "get_active_backend", _fake_get_active_backend
    )
    monkeypatch.setattr(
        pdf_backend_mod,
        "resolve_latex_template_path",
        _fake_resolve_latex_template_path,
    )
    monkeypatch.setattr(
        pdf_backend_mod, "render_latex_template", _fake_render_latex_template
    )
    monkeypatch.setattr(
        pdf_backend_mod, "render_pdfa_xmpdata", _fake_render_pdfa_xmpdata
    )
    # Force the legacy HTML fallback so we don't depend on per-tier branded
    # templates being on disk in the test environment.
    monkeypatch.setattr(
        gen_mod, "_resolve_branded_pdf_template_path", lambda _tier: None
    )

    # ``_build_branded_pdf_context`` pulls ``minimal_jinja_context_from_report_data``
    # (LLM-aware, depends on AI text slots) — short-circuit it with a deterministic
    # tier-aware dict so the LatexBackend branch sees a stable Jinja context.
    def _fake_build_branded_pdf_context(
        _data: ReportData,
        _base_context: dict[str, Any] | None,
        *,
        tier: str,
    ) -> dict[str, Any]:
        return {
            "tier": tier,
            "target": _data.target or "",
            "tenant_id": _data.tenant_id or "",
            "scan_id": _data.scan_id or "",
            "scan_completed_at": _data.created_at or "",
            "pdf_watermark": "stub-watermark",
        }

    monkeypatch.setattr(
        gen_mod, "_build_branded_pdf_context", _fake_build_branded_pdf_context
    )

    def _fake_generate_html(
        _data: ReportData,
        *,
        jinja_context: dict[str, Any] | None = None,
        tier: str | None = None,
    ) -> bytes:
        return b"<html><body>stub</body></html>"

    monkeypatch.setattr(gen_mod, "generate_html", _fake_generate_html)

    yield fake_backend


def test_generate_pdf_with_pdfa_2u_tenant_engages_pdfa_mode(
    sample_report_data: ReportData,
    stubbed_latex_pipeline: _FakeLatexBackend,
) -> None:
    """Tenant ``'pdfa-2u'`` → backend.render gets ``pdfa_mode=True``."""
    out = gen_mod.generate_pdf(
        sample_report_data,
        tier="midgard",
        pdf_archival_format="pdfa-2u",
    )

    assert out.startswith(b"%PDF"), "generate_pdf must return a PDF blob"
    assert len(stubbed_latex_pipeline.calls) == 1
    call = stubbed_latex_pipeline.calls[0]
    assert call.pdfa_mode is True, (
        "pdfa-2u tenant must trigger pdfa_mode=True at the LatexBackend"
    )
    assert call.has_xmpdata is True, (
        "pdfa-2u tenant must also forward XMP metadata to the LatexBackend"
    )
    assert call.latex_present is True, (
        "Phase-2 LaTeX template must be rendered for the pdfa-2u tenant"
    )


def test_generate_pdf_with_standard_tenant_disables_pdfa_mode(
    sample_report_data: ReportData,
    stubbed_latex_pipeline: _FakeLatexBackend,
) -> None:
    """Tenant ``'standard'`` → backend.render gets ``pdfa_mode=False``."""
    out = gen_mod.generate_pdf(
        sample_report_data,
        tier="midgard",
        pdf_archival_format="standard",
    )

    assert out.startswith(b"%PDF")
    assert len(stubbed_latex_pipeline.calls) == 1
    call = stubbed_latex_pipeline.calls[0]
    assert call.pdfa_mode is False, (
        "standard tenant must keep pdfa_mode=False at the LatexBackend"
    )
    assert call.has_xmpdata is False, (
        "standard tenant must NOT forward XMP metadata"
    )


def test_generate_pdf_standard_tenant_ignores_env_override(
    sample_report_data: ReportData,
    stubbed_latex_pipeline: _FakeLatexBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Setting ``REPORT_PDFA_MODE=1`` must NOT override a ``standard`` tenant."""
    monkeypatch.setenv("REPORT_PDFA_MODE", "1")

    out = gen_mod.generate_pdf(
        sample_report_data,
        tier="midgard",
        pdf_archival_format="standard",
    )

    assert out.startswith(b"%PDF")
    assert len(stubbed_latex_pipeline.calls) == 1
    assert stubbed_latex_pipeline.calls[0].pdfa_mode is False, (
        "standard tenant MUST take precedence over REPORT_PDFA_MODE=1"
    )


def test_generate_pdf_no_per_tenant_override_falls_back_to_env_override(
    sample_report_data: ReportData,
    stubbed_latex_pipeline: _FakeLatexBackend,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No per-tenant value → ``REPORT_PDFA_MODE`` is the only signal (test path)."""
    monkeypatch.setenv("REPORT_PDFA_MODE", "1")

    out = gen_mod.generate_pdf(
        sample_report_data,
        tier="midgard",
        # Intentionally omit ``pdf_archival_format`` to simulate a legacy
        # / test caller that has no Tenant context.
    )

    assert out.startswith(b"%PDF")
    assert len(stubbed_latex_pipeline.calls) == 1
    assert stubbed_latex_pipeline.calls[0].pdfa_mode is True, (
        "Without a per-tenant override, REPORT_PDFA_MODE=1 must engage PDF/A"
    )
