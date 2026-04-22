"""ARG-058 / B6-T01 — Render a deterministic PDF/A-2u sample report.

ARG-058-followup / C7-T02 (Wave 2) — extends the original B6-T01 renderer
with five named PDF/A-2u acceptance fixtures (``basic`` / ``cyrillic`` /
``longtable`` / ``images`` / ``per_tenant``) consumed by the
``pdfa-validation`` GitHub Actions matrix. Backwards-compatible:
``--fixture-variant=basic`` (the new default) preserves the original
tier-template render byte-for-byte so the existing CI artefacts stay
identical until a different variant is explicitly requested.

Used by the ``pdfa-validation`` GitHub Actions workflow to feed
``verapdf-cli`` a representative PDF for compliance gating, and locally
by developers verifying the LaTeX preamble changes do not regress the
PDF/A profile (``pdflatex`` + ``pdfx`` + ``colorprofiles``).

Why a dedicated entry-point instead of going through
``ReportService.generate_pdf``?

* The full service pulls in ``settings``, the LLM client, the database
  connection, and a host of optional integrations — none of which are
  needed for a static fixture render. We want CI to run on a vanilla
  TeXLive image without booting Postgres / Redis / S3 stubs.
* The script intentionally bypasses the WeasyPrint branch and drives
  :class:`LatexBackend` directly with ``pdfa_mode=True``. WeasyPrint
  cannot emit PDF/A-2u, so wiring it through here would just slow CI
  with an extra fallback step.
* Determinism: ``SOURCE_DATE_EPOCH`` is derived from the fixture's
  ``--scan-completed-at`` flag (default ``2024-01-01T00:00:00Z``), so
  the resulting PDF is byte-stable across runners and re-runs.

Usage (PowerShell):

    python -m scripts.render_pdfa_sample `
      --tier midgard `
      --fixture-variant basic `
      --output build/pdfa-sample.pdf

    # Validate locally (requires Docker):
    docker run --rm -v "${PWD}/build:/data" `
      verapdf/verapdf-cli:1.24.1 `
      --format xml --flavour 2u /data/pdfa-sample.pdf

Exit codes:
    0 — PDF rendered successfully (file size > 0).
    1 — Render failed (latexmk missing, template error, or pdfx pipeline
        produced an empty PDF).
    2 — Bad CLI arguments (unknown tier, output dir not writable, etc.).
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import struct
import sys
import tempfile
import zlib
from collections.abc import Sequence
from contextlib import ExitStack
from pathlib import Path
from typing import Any

# The script lives outside the ``src`` package, so make ``backend/`` the
# import root before pulling in :mod:`src.reports.pdf_backend`. This keeps
# the script runnable both as ``python -m scripts.render_pdfa_sample``
# (from ``backend/``) and as a plain ``python backend/scripts/...`` invocation.
_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from src.db.models import PDF_ARCHIVAL_FORMAT_DEFAULT  # noqa: E402 — sys.path edit above.
from src.reports.pdf_backend import (  # noqa: E402 — sys.path edit above.
    LatexBackend,
    render_latex_template,
    render_pdfa_xmpdata,
    resolve_latex_template_path,
)
from src.reports.tenant_pdf_format import (  # noqa: E402 — sys.path edit above.
    resolve_tenant_pdf_archival_format,
)

# C7-T02 follow-up (DEBUG-3): variants live next to the script under
# ``backend/scripts/_pdfa_fixtures.py``. Production code MUST NOT import
# from ``tests/`` — moving the registry alongside its consumer fixes the
# original dependency-inversion violation flagged by the reviewer.
from scripts._pdfa_fixtures import (  # noqa: E402 — sys.path edit above.
    PNG_TOKEN_1,
    PNG_TOKEN_2,
    VARIANTS,
    PDFAVariant,
    get_variant,
)

logger = logging.getLogger("argus.render_pdfa_sample")

# Tiers that ship a Phase-2 LaTeX template under
# ``backend/templates/reports/_latex/<tier>/main.tex.j2`` (B6-T01).
_KNOWN_TIERS: tuple[str, ...] = ("midgard", "asgard", "valhalla")

# Default deterministic timestamp — kept as a UTC epoch sentinel so
# ``SOURCE_DATE_EPOCH`` resolves to a fixed integer across runs.
_DEFAULT_SCAN_COMPLETED_AT = "2024-01-01T00:00:00+00:00"

# Static watermark for the fixture; the production renderer derives this
# from ``(tenant_id, scan_id, scan_completed_at)`` (see
# :func:`generators._compute_pdf_watermark`).
_FIXTURE_WATERMARK = "fixture-pdfa-2u"

_FIXTURE_TENANT = "argus-fixture"
_FIXTURE_SCAN = "scan-fixture-pdfa"
_FIXTURE_TARGET = "https://example.invalid"

# ARG-058-followup / C7-T02 — markers used by ``_inject_*`` helpers.
# Stable, structured, easy to grep in PR review and verapdf forensics.
_VARIANT_BODY_BEGIN = "% --- BEGIN ARGUS variant body ({variant}) ---"
_VARIANT_BODY_END = "% --- END ARGUS variant body ({variant}) ---"
_PER_TENANT_PREAMBLE_MARKER = (
    "% ARGUS per-tenant resolver: tenant_id={tenant_id} "
    "resolved_format={resolved_format}"
)


def _build_fixture_context(tier: str, scan_completed_at: str) -> dict[str, Any]:
    """Return a Jinja context that satisfies every tier template.

    The shape mirrors what ``generators._build_branded_pdf_context``
    would emit for a freshly-collected scan, but uses static fixture
    values so the resulting PDF stays byte-stable. We deliberately
    populate every optional field the templates reference (severity
    counts, OWASP rollup, KEV findings) so the fixture exercises the
    visual branches verapdf cares about (tables, links, colour spaces).
    """
    findings = [
        {
            "title": "Missing HSTS header",
            "severity": "medium",
            "cwe": "CWE-693",
            "cvss": 5.3,
            "owasp_category": "A05",
            "description": (
                "The application does not emit a Strict-Transport-Security "
                "header. An attacker on a hostile network can downgrade "
                "subsequent connections to plaintext HTTP and intercept "
                "session cookies."
            ),
        },
        {
            "title": "Reflected XSS on /search",
            "severity": "high",
            "cwe": "CWE-79",
            "cvss": 7.4,
            "owasp_category": "A03",
            "description": (
                "The ``q`` query parameter is reflected unescaped into the "
                "search result page, allowing arbitrary script execution "
                "in the victim's browser."
            ),
        },
        {
            "title": "Outdated jQuery 1.12 detected",
            "severity": "low",
            "cwe": "CWE-1104",
            "cvss": 3.1,
            "owasp_category": "A06",
            "description": (
                "The bundled jQuery copy is several major versions behind "
                "the upstream release and is missing CVE-2020-11023 fixes."
            ),
        },
    ]
    severity_counts = {
        "critical": 0,
        "high": sum(1 for f in findings if f["severity"] == "high"),
        "medium": sum(1 for f in findings if f["severity"] == "medium"),
        "low": sum(1 for f in findings if f["severity"] == "low"),
        "info": 0,
    }
    owasp_rollup = [
        {"category": "A01", "title": "Broken Access Control", "count": 0},
        {"category": "A03", "title": "Injection", "count": 1},
        {"category": "A05", "title": "Security Misconfiguration", "count": 1},
        {"category": "A06", "title": "Vulnerable Components", "count": 1},
    ]
    kev_findings = [
        {
            "rank": 1,
            "severity": "high",
            "asset": "https://example.invalid/login",
            "title": "CVE-2024-9999 — sample KEV entry for fixture only.",
        },
    ]
    ai_sections = {
        "executive_summary": (
            "ARGUS executed a Phase-2 PDF/A-2u sample render. The fixture "
            "exercises the LaTeX preamble path (pdfx + colorprofiles) and "
            "the determinism contract (SOURCE_DATE_EPOCH)."
        ),
        "key_findings": (
            "* Reflected XSS on /search (high)\n"
            "* Missing HSTS header (medium)\n"
            "* Outdated jQuery dependency (low)"
        ),
        "remediation_themes": (
            "1. Add Strict-Transport-Security with preload.\n"
            "2. Escape query parameters via the templating layer.\n"
            "3. Upgrade jQuery to >=3.7."
        ),
        "technical_analysis": (
            "Findings stem from missing baseline hardening on the edge "
            "tier; a single security-headers middleware fixes two of the "
            "three issues."
        ),
        "remediation_plan": (
            "Stage 1: ship security headers middleware.\n"
            "Stage 2: migrate front-end bundle to jQuery 3.7."
        ),
        "adversarial_posture": (
            "An external attacker chaining the XSS with cookie theft can "
            "reach session takeover within minutes; the missing HSTS "
            "header amplifies this on hostile networks."
        ),
        "strategic_recommendations": (
            "Adopt a Content Security Policy report-only deployment to "
            "surface XSS regressions before they reach production."
        ),
    }
    return {
        "tier": tier,
        "tenant_id": _FIXTURE_TENANT,
        "scan_id": _FIXTURE_SCAN,
        "target": _FIXTURE_TARGET,
        "scan_completed_at": scan_completed_at,
        "pdf_watermark": _FIXTURE_WATERMARK,
        "severity_counts": severity_counts,
        "findings": findings,
        "owasp_rollup": owasp_rollup,
        "kev_findings": kev_findings,
        "ai_sections": ai_sections,
        # ``pdfa_mode`` is the gate consumed by ``_preamble/pdfa.tex.j2``;
        # always ``True`` for this CLI — non-PDF/A renders should go
        # through the production ``generators.generate_pdf`` path.
        "pdfa_mode": True,
    }


# ---------------------------------------------------------------------------
# Deterministic 1×1 sRGB PNG generator
# ---------------------------------------------------------------------------
#
# The ``images`` variant embeds two raster images via ``\includegraphics``.
# Pillow is NOT a direct dependency in backend/requirements*.txt (it ships
# transitively under WeasyPrint via uv.lock, but the CI workflow only
# installs Jinja2 — see .github/workflows/pdfa-validation.yml). To stay
# zero-dep we synthesise valid PNG bytes from stdlib (``struct`` + ``zlib``).
#
# The PNGs are 1×1 RGB with an explicit ``sRGB`` chunk so they match the
# OutputIntent registered by ``pdfx`` via ``colorprofiles`` (sRGB
# IEC61966-2.1) — verapdf rule 6.2.4-1 fails on raster images whose
# colour-space conflicts with the document's OutputIntent.


def _png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    """Build one PNG chunk: ``length || type || data || crc32(type+data)``."""
    length = struct.pack(">I", len(data))
    crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return length + chunk_type + data + crc


def _write_deterministic_png(
    path: Path, *, red: int, green: int, blue: int
) -> Path:
    """Write a deterministic 1×1 sRGB PNG to *path* using stdlib only.

    Args:
        path: Destination filename (parent must already exist).
        red, green, blue: RGB sample values clamped to 0..255.

    Returns:
        *path* for caller convenience (chaining-friendly).

    The chunk layout is the bare minimum a PDF/A-2u-clean rendering
    pipeline needs:

    * ``IHDR`` — width=1, height=1, bit_depth=8, colour_type=2 (RGB),
      no interlace, no filter, no compression flags beyond the default.
    * ``sRGB`` — rendering-intent byte 0 (perceptual). pdfx emits a
      perceptual OutputIntent so the embedded raster matches.
    * ``IDAT`` — zlib-compressed scanline (1 filter byte + 3 RGB bytes).
    * ``IEND`` — required terminator chunk.
    """
    if not all(0 <= v <= 255 for v in (red, green, blue)):
        raise ValueError(
            f"PNG colour samples must be in 0..255; got "
            f"r={red} g={green} b={blue}"
        )

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(
        ">IIBBBBB",
        1,  # width
        1,  # height
        8,  # bit depth
        2,  # colour type: RGB
        0,  # compression method
        0,  # filter method
        0,  # interlace method
    )
    srgb = bytes([0])  # rendering intent: perceptual
    raw = bytes([0]) + bytes([red, green, blue])  # scanline filter byte + RGB
    idat = zlib.compress(raw, level=9)

    payload = (
        signature
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"sRGB", srgb)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )
    path.write_bytes(payload)
    return path


# ---------------------------------------------------------------------------
# Per-tenant resolver wrapper
# ---------------------------------------------------------------------------


def _resolve_per_tenant_format(tenant_id: str, override: str | None) -> str:
    """Synchronous wrapper around :func:`resolve_tenant_pdf_archival_format`.

    Builds a transient in-memory aiosqlite session (no migrations / seeds)
    and runs the async resolver under :func:`asyncio.run`. The transient
    session has no ``Tenant`` row for *tenant_id*, so the real resolver
    returns ``PDF_ARCHIVAL_FORMAT_DEFAULT`` (``"standard"``); we surface
    *override* as a final fallback so the per-tenant variant still embeds
    the intended ``"pdfa-2u"`` literal in the LaTeX preamble for verapdf
    to inspect.

    In unit tests :func:`resolve_tenant_pdf_archival_format` is patched
    directly (its name is bound at this module's top level), so the
    in-memory session machinery is never actually exercised — the mock
    intercepts the call and returns whatever the test wants.

    Args:
        tenant_id: Tenant identifier passed straight to the resolver.
        override: Variant-level fallback used when the resolver returns
            the default. ``None`` → fall back to
            ``PDF_ARCHIVAL_FORMAT_DEFAULT``.
    """
    try:
        from sqlalchemy.ext.asyncio import (  # noqa: PLC0415 — local import.
            AsyncSession,
            create_async_engine,
        )
    except ImportError:
        # CI workflow only installs Jinja2; sqlalchemy is in
        # backend/requirements.txt but the workflow opts out for speed.
        # Fall back to the variant override and surface a structured log
        # so the gate run is auditable.
        logger.warning(
            "tenant_resolver_skipped_no_sqlalchemy",
            extra={"event": "tenant_resolver_skipped_no_sqlalchemy"},
        )
        return override or PDF_ARCHIVAL_FORMAT_DEFAULT

    async def _run() -> str:
        engine = create_async_engine(
            "sqlite+aiosqlite:///:memory:",
            future=True,
        )
        try:
            async with AsyncSession(engine) as session:
                resolved = await resolve_tenant_pdf_archival_format(
                    session, tenant_id,
                )
        finally:
            await engine.dispose()
        # Honour the variant override when the in-memory DB has no
        # Tenant row for ``tenant_id`` — otherwise the LaTeX preamble
        # would always read "standard" and the per_tenant variant
        # would not exercise the pdfa-2u code path verapdf is meant
        # to police.
        if resolved == PDF_ARCHIVAL_FORMAT_DEFAULT and override:
            return override
        return resolved

    try:
        return asyncio.run(_run())
    except (ImportError, ModuleNotFoundError):
        # aiosqlite missing → resolve cannot run a real session.
        logger.warning(
            "tenant_resolver_skipped_no_aiosqlite",
            extra={"event": "tenant_resolver_skipped_no_aiosqlite"},
        )
        return override or PDF_ARCHIVAL_FORMAT_DEFAULT


# ---------------------------------------------------------------------------
# LaTeX source mutation helpers
# ---------------------------------------------------------------------------


def _inject_variant_body(
    latex_source: str, body: str, variant_name: str
) -> str:
    """Insert *body* immediately before ``\\end{document}``.

    The inserted block is wrapped in BEGIN/END comment markers so a
    forensic reader (``less``, ``grep -n``, verapdf rule violation
    snippets) can locate the variant content unambiguously when the
    fixture later regresses.
    """
    end_marker = "\\end{document}"
    if end_marker not in latex_source:
        raise RuntimeError(
            f"latex_source for variant {variant_name!r} is missing "
            f"\\end{{document}} marker; cannot inject body block"
        )
    block = (
        f"\n{_VARIANT_BODY_BEGIN.format(variant=variant_name)}\n"
        f"{body}\n"
        f"{_VARIANT_BODY_END.format(variant=variant_name)}\n"
    )
    return latex_source.replace(end_marker, block + end_marker, 1)


def _inject_resolved_format(
    latex_source: str, tenant_id: str, resolved_format: str
) -> str:
    """Insert a preamble comment recording the per-tenant resolved format.

    The marker lives between ``\\documentclass`` and ``\\begin{document}``
    so verapdf and forensic readers see it in the preamble. The format is
    structured-as-comment so it cannot affect compilation, but it IS
    grep-able for both unit-test assertions and human review.
    """
    begin_marker = "\\begin{document}"
    if begin_marker not in latex_source:
        raise RuntimeError(
            "latex_source missing \\begin{document} marker; cannot inject "
            "per-tenant resolved format comment"
        )
    block = (
        _PER_TENANT_PREAMBLE_MARKER.format(
            tenant_id=tenant_id, resolved_format=resolved_format
        )
        + "\n"
    )
    return latex_source.replace(begin_marker, block + begin_marker, 1)


def _build_latex_source_for_variant(
    *,
    tier: str,
    variant: PDFAVariant,
    scan_completed_at: str,
    tenant_id: str | None,
    image_paths: tuple[Path, Path] | None,
) -> str:
    """Render the LaTeX source for *variant* and apply variant-specific edits.

    Pure function (no filesystem writes other than what the underlying
    Jinja2 environment does). Extracted from :func:`main` so unit tests
    can pin a SHA-256 over the resulting LaTeX string and fail loudly
    on any drift in the renderer's composition logic.

    Args:
        tier: Tier whose ``main.tex.j2`` provides the base LaTeX shell.
        variant: One of :data:`scripts._pdfa_fixtures.VARIANTS`.
        scan_completed_at: Deterministic ISO-8601 timestamp baked into
            the rendered preamble (drives ``SOURCE_DATE_EPOCH``).
        tenant_id: Optional override for the per-tenant resolver path.
            Falls back to ``variant.tenant_id`` when ``None``.
        image_paths: Required for the ``images`` variant; ignored for
            every other variant. Two pre-generated PNG paths (caller
            owns the tempdir lifecycle).

    Returns:
        Final LaTeX source ready to hand to
        :meth:`LatexBackend.render` via ``latex_template_content``.
    """
    context = _build_fixture_context(tier, scan_completed_at)
    latex_source = render_latex_template(tier, context)

    body = variant.latex_body

    if variant.name == "images":
        if image_paths is None or len(image_paths) != 2:
            raise RuntimeError(
                "images variant requires exactly 2 pre-generated PNG paths "
                "via image_paths=(p1, p2)"
            )
        body = body.replace(PNG_TOKEN_1, image_paths[0].as_posix())
        body = body.replace(PNG_TOKEN_2, image_paths[1].as_posix())

    if variant.name == "per_tenant":
        # Resolver is consulted ONLY when --tenant-id is set OR the
        # variant carries a default tenant_id. The CLI passes the flag
        # straight through; if both are None we still resolve against
        # the variant default so the preamble carries an audit trail.
        tid = tenant_id or variant.tenant_id or _FIXTURE_TENANT
        resolved_format = _resolve_per_tenant_format(
            tid, variant.tenant_format_override,
        )
        logger.info(
            "per_tenant_format_resolved",
            extra={
                "event": "per_tenant_format_resolved",
                "tenant_id": tid,
                "resolved_format": resolved_format,
                "variant_override": variant.tenant_format_override,
            },
        )
        latex_source = _inject_resolved_format(
            latex_source, tid, resolved_format,
        )

    # Basic variant: no body injection — preserves byte-for-byte the
    # pre-C7-T02 LaTeX source so the existing CI artefacts and any
    # downstream snapshot consumers stay green.
    if variant.name != "basic":
        latex_source = _inject_variant_body(
            latex_source, body, variant.name,
        )

    return latex_source


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="render_pdfa_sample",
        description=(
            "Render a deterministic PDF/A-2u sample report for the verapdf "
            "CI gate (B6-T01 / C7-T02 fixture matrix)."
        ),
    )
    parser.add_argument(
        "--tier",
        choices=_KNOWN_TIERS,
        default="midgard",
        help=(
            "Tier template providing the base LaTeX shell. ``midgard`` is "
            "the smallest preamble and the default smoke-test surface."
        ),
    )
    parser.add_argument(
        "--fixture-variant",
        choices=sorted(VARIANTS),
        default="basic",
        help=(
            "Named PDF/A acceptance fixture (C7-T02). ``basic`` (default) "
            "is byte-identical to the pre-C7-T02 render; non-basic variants "
            "inject a variant-specific body block before \\end{document}."
        ),
    )
    parser.add_argument(
        "--tenant-id",
        default=None,
        help=(
            "Tenant identifier passed to "
            "``resolve_tenant_pdf_archival_format`` for the ``per_tenant`` "
            "variant. Ignored for every other variant."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("build") / "pdfa-sample.pdf",
        help=(
            "Destination PDF path (created if missing). Defaults to "
            "``build/pdfa-sample.pdf`` relative to the current working "
            "directory; the GitHub workflow points this at the artifact "
            "upload directory."
        ),
    )
    parser.add_argument(
        "--scan-completed-at",
        default=_DEFAULT_SCAN_COMPLETED_AT,
        help=(
            "Deterministic ISO-8601 timestamp embedded in the PDF "
            "metadata. Drives ``SOURCE_DATE_EPOCH``; do NOT pass "
            "``datetime.now()`` or the output stops being byte-stable."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Emit DEBUG-level logging (latexmk argv, jinja paths, ...).",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    tier: str = args.tier
    output: Path = args.output
    scan_completed_at: str = args.scan_completed_at
    fixture_variant: str = args.fixture_variant
    tenant_id_arg: str | None = args.tenant_id

    # ``argparse`` already validates ``choices`` so this lookup cannot
    # raise — but using ``get_variant`` keeps the failure path uniform
    # with code that imports the registry directly (e.g. tests).
    variant = get_variant(fixture_variant)

    template_path = resolve_latex_template_path(tier)
    if template_path is None:
        logger.error(
            "tier_template_missing",
            extra={"event": "tier_template_missing", "tier": tier},
        )
        return 2

    output.parent.mkdir(parents=True, exist_ok=True)

    # ExitStack guarantees the optional images-tempdir is cleaned up
    # on every exit path below (success, render failure, exception).
    with ExitStack() as stack:
        image_paths: tuple[Path, Path] | None = None
        if variant.name == "images":
            tmpdir_str = stack.enter_context(
                tempfile.TemporaryDirectory(prefix="argus-pdfa-png-")
            )
            tmpdir = Path(tmpdir_str)
            png1 = _write_deterministic_png(
                tmpdir / "argus-fixture-1.png",
                red=200, green=60, blue=60,
            )
            png2 = _write_deterministic_png(
                tmpdir / "argus-fixture-2.png",
                red=60, green=120, blue=200,
            )
            image_paths = (png1, png2)
            logger.info(
                "pdfa_images_generated",
                extra={
                    "event": "pdfa_images_generated",
                    "tmpdir": str(tmpdir),
                    "png1": png1.as_posix(),
                    "png2": png2.as_posix(),
                },
            )

        try:
            latex_source = _build_latex_source_for_variant(
                tier=tier,
                variant=variant,
                scan_completed_at=scan_completed_at,
                tenant_id=tenant_id_arg,
                image_paths=image_paths,
            )
            xmpdata_source = render_pdfa_xmpdata(
                tier, _build_fixture_context(tier, scan_completed_at),
            )
        except Exception as exc:  # noqa: BLE001 — surface as exit code 1.
            logger.error(
                "template_render_failed",
                extra={
                    "event": "template_render_failed",
                    "tier": tier,
                    "fixture_variant": variant.name,
                    "error_type": type(exc).__name__,
                },
            )
            return 1

        backend = LatexBackend()
        if not backend.is_available():
            logger.error(
                "latex_backend_unavailable",
                extra={"event": "latex_backend_unavailable"},
            )
            return 1

        ok = backend.render(
            html_content="",  # ignored when latex_template_content is set
            output_path=output,
            scan_completed_at=scan_completed_at,
            latex_template_content=latex_source,
            pdfa_mode=True,
            xmpdata_content=xmpdata_source,
        )
        if not ok or not output.exists() or output.stat().st_size == 0:
            logger.error(
                "pdfa_render_failed",
                extra={
                    "event": "pdfa_render_failed",
                    "tier": tier,
                    "fixture_variant": variant.name,
                    "output": str(output),
                },
            )
            return 1

        logger.info(
            "pdfa_render_ok",
            extra={
                "event": "pdfa_render_ok",
                "tier": tier,
                "fixture_variant": variant.name,
                "output": str(output),
                "size_bytes": output.stat().st_size,
            },
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
