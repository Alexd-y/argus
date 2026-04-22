"""ARG-058-followup / C7-T02 — PDF/A acceptance fixture variants.

Five named variants exercised by the ``pdfa-validation`` GitHub Actions
workflow against ``verapdf-cli``. Each variant defines:

* a single LaTeX body block injected verbatim into the shared PDF/A
  document shell built by :mod:`scripts.render_pdfa_sample`. There is
  no per-tier branching here — a regression in any single variant
  surfaces independently in the workflow's matrix legs.
* an optional ``tenant_id`` + ``tenant_format_override`` pair used
  exclusively by the ``per_tenant`` variant to exercise the
  ``Tenant.pdf_archival_format`` resolver path end-to-end without
  pulling a real database session into the CLI script.

Why a dedicated module
----------------------
The renderer (``backend/scripts/render_pdfa_sample.py``) and the unit
tests under ``backend/tests/scripts/`` both consume the same canonical
variant set. Centralising the data prevents drift — adding a new
variant here automatically becomes available as a CLI flag value, a
workflow matrix entry (manual edit), and a parametrisation for the
renderer/fixture tests.

C7-T02 follow-up (DEBUG-3 — dependency inversion fix)
-----------------------------------------------------
Originally lived under ``backend/tests/fixtures/pdfa_variants.py``.
Production code (the renderer) imported from a test path, inverting
the dependency direction. The module now lives next to its primary
consumer (:mod:`scripts.render_pdfa_sample`) so the import flows
``tests/ → scripts/ → src/`` instead of the inverted
``scripts/ → tests/ → src/``. The leading underscore in the module
name (``_pdfa_fixtures``) signals "internal helper of the
:mod:`scripts.render_pdfa_sample` CLI" and discourages reuse outside
the gate's matrix.

The module is import-safe both at CLI runtime (``backend/`` on
``sys.path`` after :mod:`scripts.render_pdfa_sample` injects the
project root) and under pytest collection; it has no runtime side
effects beyond constructing a small immutable mapping.

Security
~~~~~~~~
* Variant bodies are static LaTeX strings authored in this file — no
  user input is ever interpolated, so there is no injection surface
  for the renderer to worry about.
* The ``per_tenant`` variant pins ``tenant_format_override`` to the
  closed-taxonomy literal exported from :mod:`src.db.models`; if the
  project later renames the literal, ``mypy --strict`` + the model's
  own validator catch the drift before the renderer ships.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

# ``PDF_ARCHIVAL_FORMAT_VALUES`` is the closed-taxonomy tuple
# ``Tenant.pdf_archival_format`` is constrained to. Pin the per-tenant
# variant's override to the second member so it cannot drift if the
# project later renames the literal — the validator in db/models.py
# would catch that anyway, but the explicit reference here surfaces
# intent at fixture-definition time and keeps mypy --strict happy.
from src.db.models import PDF_ARCHIVAL_FORMAT_VALUES


@dataclass(frozen=True, slots=True)
class PDFAVariant:
    """One named fixture variant for the PDF/A-2u acceptance gate.

    Attributes:
        name: Identifier; matches the ``--fixture-variant`` CLI flag
            and the ``matrix.fixture`` value in
            ``.github/workflows/pdfa-validation.yml``.
        latex_body: The body block injected verbatim into the shared
            PDF/A LaTeX document shell. May contain renderer-handled
            sentinel tokens (:data:`PNG_TOKEN_1` / :data:`PNG_TOKEN_2`
            for the ``images`` variant) which are substituted with
            absolute paths to PNGs generated in a tempdir at render
            time.
        tenant_id: Tenant identifier exercised by the ``per_tenant``
            variant; ``None`` for every other variant. The renderer
            forwards this to
            :func:`src.reports.tenant_pdf_format.resolve_tenant_pdf_archival_format`.
        tenant_format_override: Per-tenant
            :data:`PDF_ARCHIVAL_FORMAT_VALUES` value the resolver
            should return for ``tenant_id``. ``None`` when the variant
            does not exercise the per-tenant path.
        description: One-line plain-English description of what the
            variant exercises. Surfaced in the CLI ``--help`` blurb
            and in the workflow log line for each matrix leg.
    """

    name: str
    latex_body: str
    tenant_id: str | None
    tenant_format_override: str | None
    description: str


# ---------------------------------------------------------------------------
# Body templates
# ---------------------------------------------------------------------------
#
# Each ``_LATEX_BODY_*`` constant is a pure LaTeX fragment — NO Jinja
# placeholders, NO Python format directives. The renderer passes it
# straight into the document shell after one optional ``str.replace``
# pass for the PNG sentinel tokens (``images`` variant only).

_LATEX_BODY_BASIC: Final[str] = (
    "ARGUS PDF/A acceptance baseline.\n"
    "\n"
    "This document is the static fixture rendered by\n"
    "\\texttt{backend/scripts/render\\_pdfa\\_sample.py} for the verapdf CI\n"
    "gate. It exercises the minimal PDF/A-2u stack (pdfx + colorprofiles\n"
    "+ hyperref-pdfa) without tier-specific layout features.\n"
)

# Cyrillic content checks T2A glyph coverage + sentence-level diacritics
# (\u0451 in lower-case ё, \u0401 in upper-case Ё). A heading + paragraph
# keeps the structural shape similar to a real Russian-language section
# so verapdf exercises font-sub-set + ToUnicode CMap behaviour, not
# just isolated glyph rendering. The block deliberately does NOT use
# ``\\begin{cyrillicblock}`` — the project's preamble configures
# Cyrillic via ``\\usepackage[T2A,T1]{fontenc}`` + ``lmodern`` (verified
# in backend/templates/reports/_latex/midgard/main.tex.j2:22), so a
# bespoke environment would only mask the real-world rendering path.
_LATEX_BODY_CYRILLIC: Final[str] = (
    "\\section*{Отчёт ARGUS --- раздел 1.1}\n"
    "\n"
    "Этот фрагмент проверяет корректность кодировки T2A и наличие\n"
    "глифов кириллицы в шрифте lmodern. Текст содержит букву ё,\n"
    "несколько прописных Ъ Ь Ы и тире --- для проверки лигатур.\n"
    "Большой Ёж сидел на пеньке и читал отчёт о безопасности.\n"
)


def _build_longtable_body() -> str:
    """Generate a 40-row longtable that forces a page break inside a table.

    ``longtable`` is the right environment here (not ``tabular``) because
    PDF/A-2u demands stable bookmark + outline structure across page
    breaks; ``tabular`` cannot break across pages so it would mask the
    failure mode this variant is targeting.
    """
    rows = "\n".join(
        f"{i} & ID-{i:04d} & описание-{i:04d} \\\\"
        for i in range(1, 41)
    )
    return (
        "\\section*{ARGUS longtable overflow fixture}\n"
        "\n"
        "Сорок строк, чтобы гарантировать перенос таблицы на следующую\n"
        "страницу — exercises bookmarks + page-break behaviour under\n"
        "PDF/A-2u with hyperref-pdfa.\n"
        "\n"
        "\\begin{longtable}{rll}\n"
        "\\toprule\n"
        "\\textbf{№} & \\textbf{ID} & \\textbf{Описание} \\\\\n"
        "\\midrule\n"
        "\\endhead\n"
        f"{rows}\n"
        "\\bottomrule\n"
        "\\end{longtable}\n"
    )


_LATEX_BODY_LONGTABLE: Final[str] = _build_longtable_body()


#: Sentinel tokens replaced by the renderer with absolute paths to PNGs
#: generated at runtime in a ``tempfile.TemporaryDirectory()``. Kept as
#: opaque ALL-CAPS strings (no ``{}`` braces) so they cannot collide
#: with LaTeX's group syntax or Python's ``str.format`` semantics.
PNG_TOKEN_1: Final[str] = "__ARGUS_PNG_PATH_1__"
PNG_TOKEN_2: Final[str] = "__ARGUS_PNG_PATH_2__"

_LATEX_BODY_IMAGES: Final[str] = (
    "\\section*{ARGUS embedded raster fixture}\n"
    "\n"
    "Two deterministic PNGs are generated at render time and embedded\n"
    "via the graphicx package. PDF/A-2u requires every image to carry\n"
    "an explicit colour-space tag; the renderer emits sRGB bytes so\n"
    "the verapdf gate exercises the OutputIntent-vs-image colour-space\n"
    "matching rule.\n"
    "\n"
    "\\begin{center}\n"
    f"\\includegraphics[width=2cm]{{{PNG_TOKEN_1}}}\\quad\n"
    f"\\includegraphics[width=2cm]{{{PNG_TOKEN_2}}}\n"
    "\\end{center}\n"
)


_LATEX_BODY_PER_TENANT: Final[str] = (
    "\\section*{ARGUS per-tenant archival path fixture}\n"
    "\n"
    "Same baseline narrative as the \\texttt{basic} variant, but rendered\n"
    "after the renderer consults\n"
    "\\texttt{src.reports.tenant\\_pdf\\_format.resolve\\_tenant\\_pdf\\_archival\\_format}\n"
    "to resolve the per-tenant override. The resolved format is logged\n"
    "and embedded as a deterministic comment in the LaTeX preamble so\n"
    "the GitHub Actions log carries an audit trail of the resolved\n"
    "value.\n"
)


# ---------------------------------------------------------------------------
# Public registry
# ---------------------------------------------------------------------------
#
# Closed-taxonomy variant set. Adding a new variant requires updating
# (1) this dict, (2) the ``--fixture-variant`` CLI ``choices`` derived
# from ``list(VARIANTS.keys())``, (3) the workflow matrix in
# ``.github/workflows/pdfa-validation.yml``, AND (4) the cardinality
# guard in ``backend/tests/scripts/test_pdfa_fixtures.py`` that asserts
# the public surface is exactly five variants.

VARIANTS: Final[dict[str, PDFAVariant]] = {
    "basic": PDFAVariant(
        name="basic",
        latex_body=_LATEX_BODY_BASIC,
        tenant_id=None,
        tenant_format_override=None,
        description=(
            "Minimal PDF/A-2u baseline — single paragraph, no Cyrillic / tables / images."
        ),
    ),
    "cyrillic": PDFAVariant(
        name="cyrillic",
        latex_body=_LATEX_BODY_CYRILLIC,
        tenant_id=None,
        tenant_format_override=None,
        description=(
            "T2A Cyrillic glyph coverage — Russian heading + paragraph with diacritics."
        ),
    ),
    "longtable": PDFAVariant(
        name="longtable",
        latex_body=_LATEX_BODY_LONGTABLE,
        tenant_id=None,
        tenant_format_override=None,
        description=(
            "40-row longtable — forces a page break inside a table to exercise "
            "bookmarks + hyperref-pdfa across page boundaries."
        ),
    ),
    "images": PDFAVariant(
        name="images",
        latex_body=_LATEX_BODY_IMAGES,
        tenant_id=None,
        tenant_format_override=None,
        description=(
            "Two raster PNGs embedded via graphicx — exercises sRGB OutputIntent "
            "matching for embedded raster images."
        ),
    ),
    "per_tenant": PDFAVariant(
        name="per_tenant",
        latex_body=_LATEX_BODY_PER_TENANT,
        tenant_id="acme",
        # ``PDF_ARCHIVAL_FORMAT_VALUES[1] == "pdfa-2u"`` — pinning to the
        # tuple member rather than the literal string so a future rename
        # of the closed-taxonomy literal triggers a mypy / runtime guard
        # before the variant ships a stale value.
        tenant_format_override=PDF_ARCHIVAL_FORMAT_VALUES[1],
        description=(
            "Per-tenant flag path — exercises Tenant.pdf_archival_format resolver "
            "via resolve_tenant_pdf_archival_format(tenant_id='acme')."
        ),
    ),
}


def get_variant(name: str) -> PDFAVariant:
    """Return the :class:`PDFAVariant` registered under *name*.

    Raises:
        KeyError: if *name* is not in :data:`VARIANTS`. The error
            message lists the valid names alphabetically so callers
            (CLI users, test parametrisations) get a discoverable
            diagnostic without grepping the source.
    """
    try:
        return VARIANTS[name]
    except KeyError:
        valid = ", ".join(sorted(VARIANTS))
        raise KeyError(
            f"unknown PDF/A fixture variant: {name!r}; valid names: [{valid}]"
        ) from None


__all__ = [
    "PDFAVariant",
    "PNG_TOKEN_1",
    "PNG_TOKEN_2",
    "VARIANTS",
    "get_variant",
]
