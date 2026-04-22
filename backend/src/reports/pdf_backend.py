"""ARG-036 / ARG-048 — PDF backend abstraction for ReportService.

Production-grade PDF rendering pipeline that decouples ``ReportService``
from any single PDF library. Three implementations live behind a single
``PDFBackend`` ``Protocol``:

* :class:`WeasyPrintBackend` — default; renders branded HTML through
  WeasyPrint. Requires Cairo + Pango + GDK-PixBuf native libs.
* :class:`LatexBackend` — fallback for CI environments where Cairo /
  Pango cannot be installed (typical Windows + minimal Linux runners).
  Requires ``latexmk`` (and ideally ``xelatex``) on ``PATH``.

  Phase-1 (ARG-036, Cycle 4) shipped as a stub that stripped HTML tags
  and wrapped the plain text in a minimal preamble. The stub is kept as
  the *fallback* path so callers without templates still get a PDF.

  Phase-2 (ARG-048, Cycle 5) wires proper ``jinja2-latex`` templates
  per tier. Callers pass ``latex_template_content`` (already-rendered
  LaTeX source produced by :func:`render_latex_template`) and the
  backend hands that source to ``latexmk -pdfxe`` (xelatex when
  available, ``-pdf`` / pdflatex otherwise).
* :class:`DisabledBackend` — graceful no-op; ``render`` returns ``False``.
  Selected automatically when neither WeasyPrint nor LaTeX is available.

Backend selection is driven by ``REPORT_PDF_BACKEND`` env var with a
fallback chain ``weasyprint → latex → disabled``. The chain is resolved
once per call (no module-level caching) so tests and operators can flip
the env var between renders without restarting the process.

Determinism contract
    * Each backend's ``render`` accepts ``scan_completed_at`` (ISO-8601)
      that maps directly to PDF ``CreationDate`` / ``ModDate`` metadata —
      ``datetime.now()`` is forbidden. Identical inputs ⇒ byte-stable
      output (modulo font-subset hashes which WeasyPrint emits per
      version; structural equality is what we test).
    * Producer / Creator strings are fixed; PDF diff'ing across releases
      requires bumping these constants in lockstep with the cycle ID.

Security
    * No subprocess shell-execution: ``subprocess.run`` always uses an
      explicit argv list (never ``shell=True``). LaTeX renders inside a
      ``tempfile.TemporaryDirectory`` so artefacts cannot leak across
      concurrent renders.
    * Native-lib errors are caught and surfaced as ``False`` (not raised)
      so callers can gracefully fall back to the chain. The ReportService
      caller maps a global ``False`` to a 503 response.
    * Phase-2 LaTeX templates run every user-controlled placeholder
      through :func:`_latex_escape` before substitution to prevent
      injection of LaTeX command sequences from tenant-supplied data.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar, Final, Mapping, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# Fixed PDF metadata — bumped only on cycle release boundaries so PDF
# diff'ing across releases is intentional, not accidental.
PDF_CREATOR: Final[str] = "ARGUS Cycle 5"
PDF_PRODUCER_WEASYPRINT: Final[str] = "WeasyPrint"
PDF_PRODUCER_LATEX: Final[str] = "LaTeX"
PDF_TITLE: Final[str] = "ARGUS Security Report"
PDF_AUTHOR: Final[str] = "ARGUS"

# Sentinel timestamp for callers that fail to provide ``scan_completed_at``.
# A fixed value is intentional — we MUST never use ``datetime.now()`` in the
# PDF metadata path (would defeat byte-stable snapshot tests).
_FALLBACK_SCAN_TIMESTAMP: Final[str] = "1970-01-01T00:00:00+00:00"

# ARG-058 — PDF/A-2u XMP metadata template basename (pdfx convention requires
# the file to be named after \jobname; we always pin \jobname to "report").
_PDFA_XMPDATA_TEMPLATE: Final[str] = "_preamble/pdfa.xmpdata.j2"
_PDFA_JOBNAME: Final[str] = "report"
_PDFA_XMPDATA_FILENAME: Final[str] = f"{_PDFA_JOBNAME}.xmpdata"

# Human-readable tier labels used in the XMP ``Title`` field. Kept in lockstep
# with the per-tier ``\hypersetup{pdftitle=...}`` lines so verapdf does not
# flag a Title/XMP mismatch.
_PDFA_TIER_LABELS: Final[dict[str, str]] = {
    "asgard": "Asgard Tier",
    "midgard": "Midgard Tier",
    "valhalla": "Valhalla Tier",
}


# --------------------------------------------------------------------------- #
# ARG-048 — LaTeX escape + template helpers (Phase-2 wiring).                 #
# --------------------------------------------------------------------------- #

#: Order matters: backslash MUST be escaped first because every other
#: replacement target uses ``\textbackslash`` etc. and would otherwise
#: get re-escaped on the second pass.
#: Sentinels for the two macros whose replacement text contains
#: ``{`` / ``}`` characters. We swap them out *before* the brace
#: replacements run so the trailing ``{}`` (which makes
#: ``\textbackslash`` / ``\textasciitilde`` / ``\textasciicircum`` swallow
#: the next space) doesn't get double-escaped into a literal ``\{\}``.
#: Sentinels use NUL bytes so they cannot collide with realistic input
#: (``str.replace`` is total over the input alphabet, and Python rejects
#: NULs in source files, so reaching this in user data requires an
#: attacker who has already broken our upstream input layer).
_BACKSLASH_SENTINEL: Final[str] = "\x00ARGUSBS\x00"
_TILDE_SENTINEL: Final[str] = "\x00ARGUSTILDE\x00"
_CARET_SENTINEL: Final[str] = "\x00ARGUSCARET\x00"
_LESS_SENTINEL: Final[str] = "\x00ARGUSLT\x00"
_GREATER_SENTINEL: Final[str] = "\x00ARGUSGT\x00"

#: Replacement table for the seven plain LaTeX special characters that
#: don't introduce ``{}`` themselves. Order matters: brace escaping must
#: come *after* the sentinel swap above.
_LATEX_ESCAPE_TABLE: Final[tuple[tuple[str, str], ...]] = (
    ("&", r"\&"),
    ("%", r"\%"),
    ("$", r"\$"),
    ("#", r"\#"),
    ("_", r"\_"),
    ("{", r"\{"),
    ("}", r"\}"),
)


def _latex_escape(value: object) -> str:
    """Escape ``value`` for safe inclusion in a LaTeX document body.

    Handles the ten LaTeX special characters plus angle brackets (which
    are interpreted as math operators in some packages). Non-string
    values are coerced via ``str()`` so callers can pass numbers / IDs
    without having to stringify upstream.

    Implementation note — *why two passes*: characters like ``\\`` map to
    ``\\textbackslash{}`` which itself contains ``{}``. A naive single-pass
    table that escapes ``{`` after ``\\`` would re-escape those braces
    into ``\\{\\}``, producing literal brace glyphs in the PDF. We therefore
    swap macros for NUL-byte sentinels first, run the brace pass, then
    swap the sentinels back. The function is *idempotent on already-safe
    text*: re-escaping a string with no special chars returns it unchanged.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = text.replace("\\", _BACKSLASH_SENTINEL)
    text = text.replace("~", _TILDE_SENTINEL)
    text = text.replace("^", _CARET_SENTINEL)
    text = text.replace("<", _LESS_SENTINEL)
    text = text.replace(">", _GREATER_SENTINEL)
    for needle, replacement in _LATEX_ESCAPE_TABLE:
        text = text.replace(needle, replacement)
    text = text.replace(_BACKSLASH_SENTINEL, r"\textbackslash{}")
    text = text.replace(_TILDE_SENTINEL, r"\textasciitilde{}")
    text = text.replace(_CARET_SENTINEL, r"\textasciicircum{}")
    text = text.replace(_LESS_SENTINEL, r"\textless{}")
    text = text.replace(_GREATER_SENTINEL, r"\textgreater{}")
    return text


def _latex_truncate(value: object, length: int = 200, suffix: str = "…") -> str:
    """Truncate ``value`` to ``length`` characters, preserving word boundaries.

    Used inside the Asgard / Valhalla longtables so a single multi-page
    finding evidence string cannot blow out the page width. Truncation
    happens *before* :func:`_latex_escape` so the suffix character is
    rendered as-is (UTF-8 ellipsis is xelatex-safe).
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if len(text) <= length:
        return text
    cut = text[:length].rsplit(" ", 1)[0]
    return f"{cut}{suffix}"


def _latex_root_directory() -> Path:
    """Return the ``backend/templates/reports/_latex`` root.

    Centralised so :func:`resolve_latex_template_path`,
    :func:`render_latex_template`, and :func:`render_pdfa_xmpdata` agree on
    the same on-disk layout. ARG-058 relies on the shared ``_preamble/``
    subtree being reachable from every per-tier template via the same
    Jinja2 loader chain.
    """
    return Path(__file__).resolve().parents[2] / "templates" / "reports" / "_latex"


def resolve_latex_template_path(tier: str) -> Path | None:
    """Return the per-tier ``main.tex.j2`` path or ``None`` when missing.

    Mirrors :func:`src.reports.generators._resolve_branded_pdf_template_path`
    for the LaTeX side. Split from :func:`render_latex_template` so callers
    can pre-flight whether to attempt Phase-2 at all (avoids importing
    Jinja2 just to check existence).
    """
    candidate = _latex_root_directory() / tier / "main.tex.j2"
    return candidate if candidate.exists() else None


def _build_latex_jinja_environment(template_dir: Path) -> Any:
    """ARG-058 — Jinja2 environment shared by tier templates and helpers.

    The loader is a *list*: per-tier directory first (so per-tier overrides
    win on name clashes), then the ``_latex`` root so shared fragments under
    ``_preamble/...`` are reachable via ``{% include '_preamble/...' %}``.

    Autoescape is disabled because the templates emit LaTeX markup; every
    user-controlled value MUST pass through ``| latex_escape`` (the same
    contract Sphinx + nbconvert use for their LaTeX output).
    """
    from jinja2 import Environment, FileSystemLoader

    env = Environment(
        loader=FileSystemLoader([str(template_dir), str(_latex_root_directory())]),
        autoescape=False,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters["latex_escape"] = _latex_escape
    env.filters["latex_truncate"] = _latex_truncate
    return env


def render_latex_template(tier_name: str, context: Mapping[str, Any]) -> str:
    """ARG-048 / ARG-058 — Render the per-tier LaTeX Jinja2 template for ``tier_name``.

    The branded LaTeX templates (``backend/templates/reports/_latex/<tier>/
    main.tex.j2``) are loaded through a dedicated Jinja2 environment that
    registers two filters used pervasively in the templates:

    * ``latex_escape`` — escape user-controlled strings.
    * ``latex_truncate`` — cap long evidence strings before they reach
      the longtable cells.

    ARG-058 — the loader chain now also includes the parent ``_latex/`` root
    so each template can ``{% include '_preamble/pdfa.tex.j2' %}`` (the shared
    PDF/A-2u stack). The include is no-op unless the caller passes
    ``pdfa_mode=True`` in ``context``.

    Args:
        tier_name: tier identifier (``"midgard"`` / ``"asgard"`` /
            ``"valhalla"``). Resolved through :func:`resolve_latex_template_path`.
        context: Jinja2 context dict (the same context as the WeasyPrint
            HTML template — see ``_build_branded_pdf_context`` in
            :mod:`src.reports.generators`).

    Returns:
        Rendered LaTeX source ready to hand to
        :meth:`LatexBackend.render` via ``latex_template_content``.

    Raises:
        FileNotFoundError: if no template exists for ``tier_name``.
        jinja2.TemplateError: on template syntax / runtime errors. The
            caller (``generate_pdf``) catches and falls back to the
            Phase-1 stub.
    """
    template_path = resolve_latex_template_path(tier_name)
    if template_path is None or not template_path.exists():
        raise FileNotFoundError(f"LaTeX template not found for tier={tier_name!r}")

    env = _build_latex_jinja_environment(template_path.parent)
    template = env.get_template(template_path.name)
    return template.render(**dict(context))


def render_pdfa_xmpdata(tier_name: str, context: Mapping[str, Any]) -> str:
    """ARG-058 — Render the XMP metadata file consumed by the ``pdfx`` package.

    pdfx looks for ``<jobname>.xmpdata`` in the same directory as the source
    ``.tex`` and serialises the keys into the PDF/A XMP metadata stream. We
    keep the template alongside the LaTeX preamble (``_preamble/pdfa.xmpdata.j2``)
    so its lifecycle is bound to the shared PDF/A preamble fragment.

    The ``tier_label`` key is auto-derived from ``tier_name`` when the caller
    has not supplied one, ensuring the XMP ``Title`` matches the
    ``\\hypersetup{pdftitle=...}`` line in each tier template.

    Args:
        tier_name: tier identifier (``"midgard"`` / ``"asgard"`` / ``"valhalla"``).
        context: Jinja2 context. ``tier``, ``tier_label``, ``creator``, and
            ``language`` are read by the template; missing keys fall back to
            sensible defaults so verapdf never fails on an empty XMP field.

    Returns:
        Rendered XMP metadata source ready to write to ``report.xmpdata``.

    Raises:
        FileNotFoundError: if the shared ``_preamble/pdfa.xmpdata.j2``
            template is missing from the deployment.
    """
    root = _latex_root_directory()
    xmpdata_path = root / _PDFA_XMPDATA_TEMPLATE
    if not xmpdata_path.exists():
        raise FileNotFoundError(f"PDF/A xmpdata template missing at {xmpdata_path}")

    enriched_context: dict[str, Any] = dict(context)
    enriched_context.setdefault("tier", tier_name)
    enriched_context.setdefault(
        "tier_label", _PDFA_TIER_LABELS.get(tier_name.lower(), tier_name.title())
    )
    enriched_context.setdefault("creator", PDF_CREATOR)

    env = _build_latex_jinja_environment(root)
    template = env.get_template(_PDFA_XMPDATA_TEMPLATE)
    return template.render(**enriched_context)


def _epoch_seconds_from_iso(timestamp: str) -> int:
    """Parse an ISO-8601 timestamp into integer epoch seconds.

    Used to seed ``SOURCE_DATE_EPOCH`` for deterministic pdfTeX builds.
    Returns ``0`` (UNIX epoch) when parsing fails so the renderer never
    crashes on a malformed ``scan_completed_at`` value — determinism still
    holds because every call with the same garbage input produces the same
    epoch (``0``).
    """
    cleaned = (timestamp or "").strip()
    if not cleaned:
        return 0
    try:
        # ``fromisoformat`` accepts both naive and aware timestamps. We
        # normalise naïves to UTC because ``SOURCE_DATE_EPOCH`` is
        # timezone-agnostic (epoch seconds, not local).
        parsed = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError:
        return 0
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    seconds = int(parsed.timestamp())
    return max(seconds, 0)


@runtime_checkable
class PDFBackend(Protocol):
    """PDF rendering backend protocol.

    Implementations MUST be stateless: a single instance can be shared
    across requests / threads. ``render`` returns ``True`` on success,
    ``False`` on graceful failure (caller maps to HTTP 503 or skips PDF
    in the bundle).

    ``name`` is declared as ``ClassVar[str]`` so concrete implementations
    are free to bind it as ``Final`` (read-only) without violating the
    protocol — Final + Protocol(name: str) clashes on the "settable
    attribute" check otherwise.
    """

    name: ClassVar[str]

    @staticmethod
    def is_available() -> bool:
        """Cheap probe: returns ``True`` only when ``render`` would succeed."""
        ...

    def render(
        self,
        *,
        html_content: str,
        output_path: Path,
        scan_completed_at: str,
        base_url: str | None = None,
        latex_template_content: str | None = None,
        pdfa_mode: bool = False,
        xmpdata_content: str | None = None,
    ) -> bool:
        """Render to ``output_path``.

        Args:
            html_content: rendered Jinja HTML, ready for the WeasyPrint
                backend. The LaTeX backend ignores this when
                ``latex_template_content`` is provided (Phase-2) and falls
                back to the Phase-1 stub (HTML → plain text → minimal
                preamble) otherwise.
            output_path: destination file (parent dir must exist).
            scan_completed_at: ISO-8601 timestamp from the source scan;
                used as PDF ``CreationDate`` for determinism. NEVER pass
                ``datetime.now()`` — a fixed sentinel is preferred.
            base_url: optional base URL for resolving relative ``url(...)``
                references in CSS (fonts, images). Forwarded by the
                WeasyPrint backend; ignored by LaTeX/Disabled.
            latex_template_content: ARG-048 Phase-2 — pre-rendered LaTeX
                source produced by :func:`render_latex_template`. When
                supplied, the LaTeX backend writes this verbatim into the
                tempfile and skips the Phase-1 HTML-to-text fallback.
                Other backends ignore the kwarg.
            pdfa_mode: ARG-058 — when ``True``, the LaTeX backend forces
                ``pdflatex`` (only engine with reliable PDF/A-2u
                compliance), exports a deterministic
                ``SOURCE_DATE_EPOCH``, and writes the XMP metadata file
                next to ``report.tex`` (see ``xmpdata_content``). Other
                backends ignore the flag because they do not produce
                PDF/A-conformant output (covered by the verapdf CI gate).
            xmpdata_content: ARG-058 — pre-rendered XMP metadata payload
                produced by :func:`render_pdfa_xmpdata`. Required when
                ``pdfa_mode=True`` so pdfx can pick it up via the
                ``\\jobname.xmpdata`` filename convention. Ignored when
                ``pdfa_mode`` is ``False``.

        Returns:
            ``True`` on success, ``False`` on graceful failure. Implementations
            MUST NOT raise on missing native deps — that is what
            :func:`get_active_backend` resolves in the fallback chain.
        """
        ...


class WeasyPrintBackend:
    """Default backend; requires Cairo + Pango + GDK-PixBuf native libs."""

    name: ClassVar[str] = "weasyprint"

    @staticmethod
    def is_available() -> bool:
        try:
            import weasyprint  # type: ignore[import-untyped]  # noqa: F401  # availability probe only
        except (ImportError, OSError):
            # ``OSError`` covers the case where the Python binding loads but
            # the underlying Pango / Cairo native libs cannot be linked
            # (typical Windows host without GTK runtime).
            return False
        return True

    def render(
        self,
        *,
        html_content: str,
        output_path: Path,
        scan_completed_at: str,
        base_url: str | None = None,
        latex_template_content: str | None = None,
        pdfa_mode: bool = False,
        xmpdata_content: str | None = None,
    ) -> bool:
        # ``latex_template_content`` / ``pdfa_mode`` / ``xmpdata_content`` are
        # part of the unified Protocol but meaningless for an HTML backend.
        # WeasyPrint cannot emit PDF/A-2u; the verapdf CI gate operates on the
        # LaTeX backend output exclusively. Silently ignoring these kwargs
        # keeps the call sites uniform.
        del latex_template_content, pdfa_mode, xmpdata_content
        try:
            from weasyprint import HTML
        except (ImportError, OSError) as exc:
            logger.warning(
                "weasyprint_import_failed",
                extra={
                    "event": "weasyprint_import_failed",
                    "error_type": type(exc).__name__,
                },
            )
            return False
        creation_date = (scan_completed_at or _FALLBACK_SCAN_TIMESTAMP).strip()
        try:
            html = (
                HTML(string=html_content, base_url=base_url)
                if base_url
                else HTML(string=html_content)
            )
            html.write_pdf(
                target=str(output_path),
                # PDF determinism: every metadata field is derived from the scan
                # input (or a fixed constant). No wall-clock timestamps.
                metadata={
                    "creator": PDF_CREATOR,
                    "title": PDF_TITLE,
                    "authors": [PDF_AUTHOR],
                    "subject": "Security assessment report",
                    "created": creation_date,
                    "modified": creation_date,
                },
            )
        except Exception as exc:  # weasyprint surfaces a wide error variety
            logger.exception(
                "weasyprint_render_failed",
                extra={
                    "event": "weasyprint_render_failed",
                    "error_type": type(exc).__name__,
                },
            )
            return False
        return output_path.exists() and output_path.stat().st_size > 0


class LatexBackend:
    """Fallback PDF backend driven by ``latexmk``.

    Two render modes share a single ``render`` entrypoint:

    * **Phase-2 (ARG-048, Cycle 5)** — the preferred path. Callers pass
      ``latex_template_content`` (already-rendered LaTeX source produced
      by :func:`render_latex_template`). The source is written verbatim
      to a tempfile, ``latexmk`` is invoked with ``xelatex`` when
      available (``-pdfxe``) and ``pdflatex`` (``-pdf``) otherwise, and
      the resulting PDF is moved to ``output_path``.

    * **Phase-1 (ARG-036, Cycle 4) — fallback** — for callers that
      cannot produce LaTeX templates (legacy code paths, ad-hoc tests),
      :meth:`_wrap_minimal_latex` strips HTML tags and wraps the plain
      text in a minimal preamble. Output is a one-column plain-text PDF
      — enough to keep the dispatch chain healthy on a host without
      WeasyPrint deps.

    The Phase-1 fallback is kept on purpose — removing it would silently
    break callers that haven't migrated to the Phase-2 templates yet. The
    ``LATEX_PHASE`` constant on this class is intended for diagnostics /
    metric labels that want to record which path a given render took.
    """

    name: ClassVar[str] = "latex"
    _LATEXMK_TIMEOUT_SECONDS: Final[int] = 180  # xelatex needs a bigger budget

    #: Tag attached to log records so operators can grep render mode.
    LATEX_PHASE_TEMPLATE: Final[str] = "phase2-template"
    LATEX_PHASE_FALLBACK: Final[str] = "phase1-fallback"

    @staticmethod
    def is_available() -> bool:
        return shutil.which("latexmk") is not None

    @staticmethod
    def _engine_flag(*, pdfa_mode: bool = False) -> str:
        """Return the ``latexmk`` engine flag for the current host.

        Prefers ``xelatex`` (``-pdfxe``) because the Phase-2 templates
        rely on ``\\usepackage[T1]{fontenc}`` + ``lmodern`` which xelatex
        handles correctly with UTF-8 input out-of-the-box. Falls back to
        ``pdflatex`` (``-pdf``) when xelatex is not on ``PATH``.

        ARG-058 — when ``pdfa_mode`` is set we ALWAYS pick ``pdflatex``.
        ``pdfx`` + ``colorprofiles`` ship the most reliable PDF/A-2u
        OutputIntent code path on pdfTeX; xelatex's ``\\special{pdf:...}``
        backend is functional but more brittle (TeXLive 2024 still warns
        about missing colorprofiles autodetection in some xelatex builds).
        """
        if pdfa_mode:
            return "-pdf"
        return "-pdfxe" if shutil.which("xelatex") is not None else "-pdf"

    def render(
        self,
        *,
        html_content: str,
        output_path: Path,
        scan_completed_at: str,
        base_url: str | None = None,
        latex_template_content: str | None = None,
        pdfa_mode: bool = False,
        xmpdata_content: str | None = None,
    ) -> bool:
        # ``base_url`` does not apply: LaTeX resolves \input / \include
        # relative to the tempdir, and the templates do not pull external
        # assets. Documented in the docstring.
        del base_url
        if shutil.which("latexmk") is None:
            logger.warning(
                "latexmk_unavailable",
                extra={"event": "latexmk_unavailable"},
            )
            return False

        if latex_template_content is not None and latex_template_content.strip():
            tex_source = latex_template_content
            phase = self.LATEX_PHASE_TEMPLATE
        else:
            tex_source = self._wrap_minimal_latex(html_content, scan_completed_at)
            phase = self.LATEX_PHASE_FALLBACK

        # ARG-058 — PDF/A-2u requires the pre-rendered xmpdata payload to be
        # present alongside the .tex file (pdfx looks it up by basename).
        # Reject early so we never compile a partial PDF/A document that
        # would slip past the verapdf gate with empty XMP fields.
        if pdfa_mode and not (xmpdata_content and xmpdata_content.strip()):
            logger.warning(
                "pdfa_xmpdata_missing",
                extra={"event": "pdfa_xmpdata_missing", "phase": phase},
            )
            return False

        engine_flag = self._engine_flag(pdfa_mode=pdfa_mode)

        with tempfile.TemporaryDirectory(prefix="argus-latex-") as tmpdir:
            tmp_dir = Path(tmpdir)
            tmp_tex = tmp_dir / f"{_PDFA_JOBNAME}.tex"
            tmp_tex.write_text(tex_source, encoding="utf-8")
            if pdfa_mode and xmpdata_content is not None:
                # pdfx convention: <\jobname>.xmpdata in the same directory.
                # The ``\jobname`` resolves to ``report`` because we always
                # write the source as ``report.tex`` — keeps the xmpdata
                # filename deterministic across renders.
                (tmp_dir / _PDFA_XMPDATA_FILENAME).write_text(
                    xmpdata_content, encoding="utf-8"
                )

            try:
                result = subprocess.run(  # noqa: S603 — argv is explicit, no shell.
                    [
                        "latexmk",
                        engine_flag,
                        "-interaction=nonstopmode",
                        "-halt-on-error",
                        f"-output-directory={tmp_dir}",
                        str(tmp_tex),
                    ],
                    check=False,
                    capture_output=True,
                    timeout=self._LATEXMK_TIMEOUT_SECONDS,
                    env=self._build_subprocess_env(scan_completed_at),
                    cwd=str(tmp_dir),
                )
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
                logger.warning(
                    "latexmk_invocation_failed",
                    extra={
                        "event": "latexmk_invocation_failed",
                        "error_type": type(exc).__name__,
                        "phase": phase,
                        "engine_flag": engine_flag,
                        "pdfa_mode": pdfa_mode,
                    },
                )
                return False
            if result.returncode != 0:
                logger.warning(
                    "latexmk_nonzero_exit",
                    extra={
                        "event": "latexmk_nonzero_exit",
                        "return_code": result.returncode,
                        "phase": phase,
                        "engine_flag": engine_flag,
                        "pdfa_mode": pdfa_mode,
                    },
                )
                return False
            tmp_pdf = tmp_dir / f"{_PDFA_JOBNAME}.pdf"
            if not tmp_pdf.exists() or tmp_pdf.stat().st_size == 0:
                return False
            output_path.write_bytes(tmp_pdf.read_bytes())
        logger.info(
            "latex_render_ok",
            extra={
                "event": "latex_render_ok",
                "phase": phase,
                "engine_flag": engine_flag,
                "pdfa_mode": pdfa_mode,
            },
        )
        return output_path.exists() and output_path.stat().st_size > 0

    @staticmethod
    def _build_subprocess_env(scan_completed_at: str) -> dict[str, str]:
        """ARG-058 — Build the environment dict for the ``latexmk`` subprocess.

        Always exports ``SOURCE_DATE_EPOCH`` derived from
        ``scan_completed_at`` — pdfTeX honours the variable to emit
        deterministic ``/CreationDate``, ``/ModDate``, and ``/ID`` fields.
        We propagate the parent process env (``PATH``, TeX environment
        variables, etc.) and only override the timestamp variable so the
        change is invisible to non-TeX subprocesses.

        ``SOURCE_DATE_EPOCH`` applies to BOTH pdflatex and xelatex on
        TeX Live 2024+, so we keep it set even when ``pdfa_mode`` is
        False — making the legacy LaTeX path equally deterministic at
        no extra cost.
        """
        env = os.environ.copy()
        env["SOURCE_DATE_EPOCH"] = str(_epoch_seconds_from_iso(scan_completed_at))
        # ``FORCE_SOURCE_DATE`` is a belt-and-braces flag — older pdfTeX
        # builds (< 1.40.21) only act on SOURCE_DATE_EPOCH when this is set.
        env["FORCE_SOURCE_DATE"] = "1"
        return env

    @staticmethod
    def _wrap_minimal_latex(html_content: str, scan_completed_at: str) -> str:
        """Phase-1 fallback: collapse HTML to plain text and wrap in LaTeX.

        Only used when ``latex_template_content`` is *not* provided. The
        Phase-2 path (ARG-048) replaces this with full per-tier
        templates rendered through :func:`render_latex_template`.
        """
        text = re.sub(r"<[^>]+>", " ", html_content)
        text = re.sub(r"\s+", " ", text).strip()
        text = _latex_escape(text)
        timestamp = _latex_escape(scan_completed_at or _FALLBACK_SCAN_TIMESTAMP)
        return (
            r"\documentclass[a4paper,11pt]{article}" + "\n"
            r"\usepackage[utf8]{inputenc}" + "\n"
            r"\usepackage[T1]{fontenc}" + "\n"
            r"\usepackage{geometry}" + "\n"
            r"\geometry{margin=2cm}" + "\n"
            r"\title{" + _latex_escape(PDF_TITLE) + "}" + "\n"
            r"\author{" + _latex_escape(PDF_AUTHOR) + "}" + "\n"
            r"\date{" + timestamp + "}" + "\n"
            r"\begin{document}" + "\n"
            r"\maketitle" + "\n" + text + "\n"
            r"\end{document}" + "\n"
        )


class DisabledBackend:
    """Graceful no-op backend.

    Selected automatically when neither WeasyPrint nor LaTeX is available
    on the host. ``render`` always returns ``False`` so the caller can
    surface a 503 / skip the PDF format from the bundle.
    """

    name: ClassVar[str] = "disabled"

    @staticmethod
    def is_available() -> bool:
        return True

    def render(
        self,
        *,
        html_content: str,
        output_path: Path,
        scan_completed_at: str,
        base_url: str | None = None,
        latex_template_content: str | None = None,
        pdfa_mode: bool = False,
        xmpdata_content: str | None = None,
    ) -> bool:
        # All inputs are ignored by design; the disabled backend never
        # writes anything. ``del`` keeps the linter quiet.
        del html_content, output_path, scan_completed_at, base_url
        del latex_template_content, pdfa_mode, xmpdata_content
        return False


# Registry keyed by ``REPORT_PDF_BACKEND`` env-var values. The order in
# ``_FALLBACK_CHAIN`` is what :func:`get_active_backend` walks when the
# requested backend is unavailable.
_BACKEND_REGISTRY: Final[
    dict[str, type[WeasyPrintBackend | LatexBackend | DisabledBackend]]
] = {
    WeasyPrintBackend.name: WeasyPrintBackend,
    LatexBackend.name: LatexBackend,
    DisabledBackend.name: DisabledBackend,
}

_FALLBACK_CHAIN: Final[tuple[str, ...]] = (
    WeasyPrintBackend.name,
    LatexBackend.name,
    DisabledBackend.name,
)

ENV_VAR_BACKEND: Final[str] = "REPORT_PDF_BACKEND"
DEFAULT_BACKEND_NAME: Final[str] = WeasyPrintBackend.name


def list_backend_names() -> tuple[str, ...]:
    """Return the canonical backend identifiers in fallback-chain order."""
    return _FALLBACK_CHAIN


def get_active_backend() -> PDFBackend:
    """Resolve the active PDF backend.

    Reads ``REPORT_PDF_BACKEND`` (case-insensitive). If the requested
    backend is unavailable, walks the fallback chain
    ``weasyprint → latex → disabled``. The disabled backend is always
    available, so this function NEVER raises.
    """
    requested = os.environ.get(ENV_VAR_BACKEND, DEFAULT_BACKEND_NAME).strip().lower()
    backend_cls = _BACKEND_REGISTRY.get(requested)
    if backend_cls is not None and backend_cls.is_available():
        return backend_cls()
    for fallback_name in _FALLBACK_CHAIN:
        candidate = _BACKEND_REGISTRY[fallback_name]
        if candidate.is_available():
            return candidate()
    # _FALLBACK_CHAIN ends with DisabledBackend whose ``is_available`` is
    # ``True`` unconditionally, so the loop above always returns. This
    # statement is unreachable in practice; it exists for mypy --strict.
    return DisabledBackend()


__all__ = [
    "DEFAULT_BACKEND_NAME",
    "ENV_VAR_BACKEND",
    "PDF_AUTHOR",
    "PDF_CREATOR",
    "PDF_PRODUCER_LATEX",
    "PDF_PRODUCER_WEASYPRINT",
    "PDF_TITLE",
    "DisabledBackend",
    "LatexBackend",
    "PDFBackend",
    "WeasyPrintBackend",
    "get_active_backend",
    "list_backend_names",
    "render_latex_template",
    "resolve_latex_template_path",
]
