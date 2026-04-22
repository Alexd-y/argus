"""ARG-058 / B6-T01 — Render a deterministic PDF/A-2u sample report.

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
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

# The script lives outside the ``src`` package, so make ``backend/`` the
# import root before pulling in :mod:`src.reports.pdf_backend`. This keeps
# the script runnable both as ``python -m scripts.render_pdfa_sample``
# (from ``backend/``) and as a plain ``python backend/scripts/...`` invocation.
_BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(_BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(_BACKEND_ROOT))

from src.reports.pdf_backend import (  # noqa: E402 — sys.path edit above.
    LatexBackend,
    render_latex_template,
    render_pdfa_xmpdata,
    resolve_latex_template_path,
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


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="render_pdfa_sample",
        description=(
            "Render a deterministic PDF/A-2u sample report for the "
            "verapdf CI gate (B6-T01)."
        ),
    )
    parser.add_argument(
        "--tier",
        choices=_KNOWN_TIERS,
        default="midgard",
        help=(
            "Tier template to render. ``midgard`` is the default because "
            "it is the smallest preamble and is therefore the fastest "
            "smoke-test surface for the CI gate."
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

    template_path = resolve_latex_template_path(tier)
    if template_path is None:
        logger.error(
            "tier_template_missing",
            extra={"event": "tier_template_missing", "tier": tier},
        )
        return 2

    output.parent.mkdir(parents=True, exist_ok=True)

    context = _build_fixture_context(tier, scan_completed_at)
    try:
        latex_source = render_latex_template(tier, context)
        xmpdata_source = render_pdfa_xmpdata(tier, context)
    except Exception as exc:  # noqa: BLE001 — surface as exit code 1.
        logger.error(
            "template_render_failed",
            extra={
                "event": "template_render_failed",
                "tier": tier,
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
                "output": str(output),
            },
        )
        return 1

    logger.info(
        "pdfa_render_ok",
        extra={
            "event": "pdfa_render_ok",
            "tier": tier,
            "output": str(output),
            "size_bytes": output.stat().st_size,
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
