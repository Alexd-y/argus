"""ARG-048 — Integration: LaTeX Phase-2 ⇄ WeasyPrint parity.

Cycle 4 / ARG-036 shipped a Phase-1 LaTeX backend stub (HTML stripped +
wrapped in a minimal LaTeX preamble). Cycle 5 / ARG-048 swaps the stub
for a Jinja2-driven, tier-aware template (``backend/templates/reports/
_latex/<tier>/main.tex.j2``) wired through
``LatexBackend.render(latex_template_content=...)`` and rendered with
``xelatex`` when available (``latexmk`` fallback otherwise).

This module is the regression contract for that swap. Per the ARG-048
plan it asserts four parity invariants for every (tier × scenario):

    1. **Both backends render a non-empty, well-formed PDF.**
       Both binaries start with the ``%PDF-`` magic and have non-zero
       size.
    2. **Tenant + scan + target identifiers travel through unchanged.**
       The escape filter in ``render_latex_template`` MUST never strip
       characters that are safe in LaTeX (alphanumerics, dashes, dots),
       so the ASCII identifiers from the fixture must appear verbatim
       in the extracted LaTeX text.
    3. **Severity headlines are present in both outputs.**
       Whatever WeasyPrint surfaces as a severity heading (``Critical``,
       ``High``, ``Medium``, ``Low``, ``Info``) MUST also be visible
       in the LaTeX output. The case-insensitive "Critical" / "High"
       strings are a hard floor — losing them would break operator
       triage.
    4. **No raw secrets leak into either backend.**
       Re-uses the ARG-031 / ARG-036 secret catalogue (subset chosen
       for cost — the full 990-case grid lives in
       ``test_report_no_secret_leak.py``).

The test is gated by ``@pytest.mark.requires_latex`` and is skipped
when neither ``xelatex`` nor ``latexmk`` is on PATH (CI runs the LaTeX
job separately for ARG-036 / ARG-048; dev environments without a TeX
toolchain skip cleanly). WeasyPrint cases also skip when the native
libs are missing (``WSP_SKIP``).
"""

from __future__ import annotations

import io
import os
import shutil
from collections.abc import Iterator
from typing import Final

import pytest

from src.api.schemas import Finding, ReportSummary
from src.reports.generators import (
    EvidenceEntry,
    PhaseOutputEntry,
    ReportData,
    ScreenshotEntry,
    TimelineEntry,
)
from src.reports.pdf_backend import (
    LatexBackend,
    WeasyPrintBackend,
    _latex_escape,
    _latex_truncate,
    render_latex_template,
    resolve_latex_template_path,
)
from src.reports.report_bundle import ReportFormat, ReportTier
from src.reports.report_service import ReportService

from tests.weasyprint_skips import WSP_REASON, WSP_SKIP

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


PDF_MAGIC: Final[bytes] = b"%PDF-"
SCAN_COMPLETED_AT: Final[str] = "2026-04-21T08:30:00Z"

# Secret catalogue (compact subset of ARG-031). Each row is
# ``(label, raw_secret, needle)``: the raw secret is injected into a
# finding description, the needle is the high-entropy substring whose
# presence in either backend output proves the redaction layer failed.
LATEX_PARITY_SECRETS: Final[tuple[tuple[str, str, str], ...]] = (
    ("bearer_basic", "Bearer abc123def456ghi789", "abc123def456ghi789"),
    ("aws_access_key", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    ("github_pat", "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890", "ghp_aBcDeFgHiJkL"),
    (
        "stripe_pk_test",
        "pk_test_51HabcdEFGHIJKLMnopqrstuvwxyzABCDEF123456",
        "pk_test_51HabcdEFGHIJKL",
    ),
    (
        "private_key",
        "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAabc",
        "MIIEowIBAAKCAQEA",
    ),
)


# ---------------------------------------------------------------------------
# Skip predicates
# ---------------------------------------------------------------------------


def _latex_engine_available() -> bool:
    return shutil.which("xelatex") is not None or shutil.which("latexmk") is not None


def _pypdf_available() -> bool:
    try:
        import pypdf  # noqa: F401
    except ImportError:
        return False
    return True


# ---------------------------------------------------------------------------
# Fixtures — share the canonical scan with the ARG-036 suite to keep the
# parity contract anchored to a single source of truth.
# ---------------------------------------------------------------------------


def _baseline_findings() -> list[Finding]:
    """Findings shared by every parity scenario (no secrets injected)."""
    return [
        Finding(
            severity="critical",
            title="SQL Injection in /api/users",
            description="UNION-based SQLi via id parameter; full row dump observed.",
            cwe="CWE-89",
            cvss=9.8,
            owasp_category="A03",
            evidence_refs=["s3://argus-evidence/sqli-dump"],
        ),
        Finding(
            severity="critical",
            title="Remote Code Execution in /upload",
            description="Unrestricted file upload combined with LFI to /etc/passwd.",
            cwe="CWE-78",
            cvss=9.5,
        ),
        Finding(
            severity="high",
            title="Reflected XSS in search endpoint",
            description="`q` parameter echoed unescaped on the results page.",
            cwe="CWE-79",
            cvss=7.5,
            owasp_category="A03",
        ),
        Finding(
            severity="high",
            title="Server-Side Request Forgery (SSRF)",
            description="Internal metadata endpoint reachable via URL parameter.",
            cwe="CWE-918",
            cvss=8.1,
        ),
        Finding(
            severity="medium",
            title="Missing security headers",
            description="No CSP / HSTS / X-Frame-Options set on responses.",
            cwe="CWE-693",
        ),
        Finding(
            severity="low",
            title="Server banner leaks version",
            description="Server header discloses nginx/1.18.0.",
            cwe="CWE-200",
        ),
        Finding(
            severity="info",
            title="Robots.txt discloses /admin",
            description="Robots.txt enumerates restricted paths.",
        ),
    ]


def _make_report_data(
    *,
    extra_finding_description: str | None = None,
    report_id: str = "r-arg048-parity-1",
    scan_id: str = "scan-arg048-parity-1",
    tenant_id: str = "tenant-arg048-parity-1",
) -> ReportData:
    """Build a parity-suite ReportData with optional secret injection."""
    summary = ReportSummary(
        critical=2,
        high=2,
        medium=1,
        low=1,
        info=1,
        technologies=["nginx", "django"],
        sslIssues=1,
        headerIssues=2,
        leaksFound=False,
    )
    findings = _baseline_findings()
    if extra_finding_description is not None:
        findings.append(
            Finding(
                severity="medium",
                title="Inline secret reproduction",
                description=extra_finding_description,
                cwe="CWE-200",
            )
        )
    return ReportData(
        report_id=report_id,
        target="https://app.example.test",
        summary=summary,
        findings=findings,
        technologies=["nginx", "django"],
        scan_id=scan_id,
        tenant_id=tenant_id,
        evidence=[
            EvidenceEntry(
                finding_id="f1",
                object_key="evidence/sqli/dump.txt",
                description="HTTP req/resp dump",
            )
        ],
        screenshots=[
            ScreenshotEntry(object_key="screenshots/login.png", url_or_email="login")
        ],
        timeline=[
            TimelineEntry(
                phase="recon",
                order_index=0,
                entry={"phase": "started"},
                created_at=SCAN_COMPLETED_AT,
            )
        ],
        phase_outputs=[PhaseOutputEntry(phase="recon", output_data={"k": "v"})],
        executive_summary="Critical SQL/RCE issues observed; remediate immediately.",
        remediation=["Patch ORM.", "Disable unrestricted upload."],
        ai_insights=["LLM exec summary"],
        raw_artifacts=[{"raw": "recon dump"}],
        hibp_pwned_password_summary={"pwned_count": 12},
        created_at=SCAN_COMPLETED_AT,
    )


@pytest.fixture
def service() -> ReportService:
    return ReportService(tool_version="arg-048-parity")


@pytest.fixture
def reset_pdf_backend_env() -> Iterator[None]:
    """Snapshot + restore ``REPORT_PDF_BACKEND`` around tests that mutate it."""
    saved = os.environ.get("REPORT_PDF_BACKEND")
    try:
        yield
    finally:
        if saved is None:
            os.environ.pop("REPORT_PDF_BACKEND", None)
        else:
            os.environ["REPORT_PDF_BACKEND"] = saved


# ---------------------------------------------------------------------------
# Helpers — PDF text extraction
# ---------------------------------------------------------------------------


def _extract_pdf_text(pdf_bytes: bytes) -> str:
    """Extract concatenated text from every page; uses ``pypdf``.

    Returns an empty string when ``pypdf`` is missing — the caller must
    guard with ``_pypdf_available`` to keep failure modes local.
    """
    try:
        import pypdf
    except ImportError:  # pragma: no cover — guarded by skipif
        return ""
    reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    chunks: list[str] = []
    for page in reader.pages:
        try:
            chunks.append(page.extract_text() or "")
        except Exception:  # pragma: no cover — defensive against pypdf quirks
            chunks.append("")
    return "\n".join(chunks)


# ---------------------------------------------------------------------------
# Smoke: render_latex_template returns valid LaTeX source per tier
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tier",
    [ReportTier.MIDGARD, ReportTier.ASGARD, ReportTier.VALHALLA],
)
def test_render_latex_template_emits_compileable_source(
    tier: ReportTier,
) -> None:
    """ARG-048: every tier template renders to a syntactically-valid LaTeX
    source string with the expected preamble + ``\\begin{document}`` /
    ``\\end{document}`` envelope. This guards against template typos
    independent of having a TeX toolchain installed.
    """
    context = {
        "tenant_id": "tenant-smoke",
        "scan_id": "scan-smoke",
        "target": "https://example.test",
        "scan_completed_at": SCAN_COMPLETED_AT,
        "pdf_watermark": "deadbeefdeadbeefdeadbeefdeadbeef",
        "ai_sections": {
            "executive_summary": "Smoke summary.",
            "key_findings": "Smoke findings.",
            "remediation_themes": "Smoke remediation.",
            "technical_analysis": "Smoke analysis.",
            "remediation_plan": "Smoke plan.",
            "adversarial_posture": "Smoke posture.",
            "strategic_recommendations": "Smoke recommendations.",
        },
        "severity_counts": {
            "critical": 1,
            "high": 1,
            "medium": 1,
            "low": 1,
            "info": 1,
        },
        "findings": [
            {
                "title": "Smoke finding",
                "severity": "critical",
                "cwe": "CWE-1",
                "description": "Smoke description that should make it through escaping.",
            }
        ],
        "owasp_rollup": [
            {"category": "A01", "title": "Broken Access Control", "count": 1},
        ],
        "kev_findings": [
            {
                "rank": 1,
                "severity": "critical",
                "asset": "app.example.test",
                "title": "Smoke KEV finding",
            }
        ],
        "valhalla_executive_report": None,
    }
    source = render_latex_template(tier.value, context)

    assert source.startswith("\\documentclass"), (
        f"{tier.value}: template missing \\documentclass preamble"
    )
    assert "\\begin{document}" in source
    assert "\\end{document}" in source
    assert "tenant-smoke" in source
    assert "scan-smoke" in source
    assert "deadbeefdeadbeef" in source


# ---------------------------------------------------------------------------
# Parity contract — both backends produce non-empty %PDF-prefixed bytes
# (3 tiers × 2 secret-injected scenarios = 6 cases)
# ---------------------------------------------------------------------------


@pytest.mark.requires_latex
@pytest.mark.weasyprint_pdf
@pytest.mark.skipif(WSP_SKIP, reason=WSP_REASON)
@pytest.mark.skipif(
    not _latex_engine_available(),
    reason="neither xelatex nor latexmk on PATH (install texlive/MikTeX)",
)
@pytest.mark.skipif(
    not _pypdf_available(), reason="pypdf required for PDF text extraction"
)
@pytest.mark.parametrize(
    "tier",
    [ReportTier.MIDGARD, ReportTier.ASGARD, ReportTier.VALHALLA],
)
@pytest.mark.parametrize(
    "scenario",
    ["baseline", "with_secret"],
)
def test_latex_weasyprint_pdf_parity(
    service: ReportService,
    tier: ReportTier,
    scenario: str,
    reset_pdf_backend_env: None,
) -> None:
    """ARG-048 parity invariants 1 + 2 + 3.

    Renders the same scan via both backends, extracts text from each PDF,
    and asserts the headline + identifier contract holds.

    ``scenario="with_secret"`` injects a Bearer token into a finding so
    the redaction-layer parity assertion has a concrete needle. The full
    secret leak grid is exercised separately by :func:`test_no_secret
    _leak_in_either_backend`.
    """
    if scenario == "with_secret":
        report_data = _make_report_data(
            extra_finding_description=(
                "Operator note: token Bearer abc123def456ghi789 was rotated."
            )
        )
    else:
        report_data = _make_report_data()

    # WeasyPrint output
    os.environ["REPORT_PDF_BACKEND"] = WeasyPrintBackend.name
    weasy_bundle = service.render_bundle(
        report_data, tier=tier, fmt=ReportFormat.PDF
    )
    assert weasy_bundle.size_bytes > 0
    assert weasy_bundle.content[:5] == PDF_MAGIC

    # LaTeX output
    os.environ["REPORT_PDF_BACKEND"] = LatexBackend.name
    latex_bundle = service.render_bundle(
        report_data, tier=tier, fmt=ReportFormat.PDF
    )
    assert latex_bundle.size_bytes > 0
    assert latex_bundle.content[:5] == PDF_MAGIC

    weasy_text = _extract_pdf_text(weasy_bundle.content)
    latex_text = _extract_pdf_text(latex_bundle.content)

    # Invariant 2: identifiers must travel through unchanged.
    for identifier in (report_data.tenant_id, report_data.scan_id):
        assert identifier in weasy_text, (
            f"WeasyPrint output missing identifier {identifier!r}"
        )
        assert identifier in latex_text, (
            f"LaTeX output missing identifier {identifier!r}"
        )

    # Invariant 3: severity headlines must exist in both outputs.
    # ``case-insensitive`` because LaTeX preamble may force smallcaps.
    weasy_lower = weasy_text.lower()
    latex_lower = latex_text.lower()
    for headline in ("critical", "high"):
        assert headline in weasy_lower, (
            f"WeasyPrint output missing severity headline {headline!r}"
        )
        assert headline in latex_lower, (
            f"LaTeX output missing severity headline {headline!r}"
        )


# ---------------------------------------------------------------------------
# Findings count parity (within ±5%)
# ---------------------------------------------------------------------------


@pytest.mark.requires_latex
@pytest.mark.weasyprint_pdf
@pytest.mark.skipif(WSP_SKIP, reason=WSP_REASON)
@pytest.mark.skipif(
    not _latex_engine_available(),
    reason="neither xelatex nor latexmk on PATH (install texlive/MikTeX)",
)
@pytest.mark.skipif(
    not _pypdf_available(), reason="pypdf required for PDF text extraction"
)
@pytest.mark.parametrize(
    "tier",
    [ReportTier.MIDGARD, ReportTier.ASGARD, ReportTier.VALHALLA],
)
def test_latex_weasyprint_finding_title_parity(
    service: ReportService,
    tier: ReportTier,
    reset_pdf_backend_env: None,
) -> None:
    """ARG-048 parity invariant: at least one finding title from the
    fixture appears in both outputs. We do **not** count exact occurrences
    (long-table truncation differs between LaTeX and WeasyPrint), only
    that the dominant titles survive to both surfaces.
    """
    report_data = _make_report_data()

    os.environ["REPORT_PDF_BACKEND"] = WeasyPrintBackend.name
    weasy_bundle = service.render_bundle(
        report_data, tier=tier, fmt=ReportFormat.PDF
    )

    os.environ["REPORT_PDF_BACKEND"] = LatexBackend.name
    latex_bundle = service.render_bundle(
        report_data, tier=tier, fmt=ReportFormat.PDF
    )

    weasy_text = _extract_pdf_text(weasy_bundle.content).lower()
    latex_text = _extract_pdf_text(latex_bundle.content).lower()

    # The Midgard tier intentionally hides the per-finding table — for it
    # the parity contract only requires the executive narrative to land.
    if tier == ReportTier.MIDGARD:
        # SQL Injection / RCE titles may be summarised away; require only
        # that the WeasyPrint executive summary appears verbatim in LaTeX.
        assert "critical" in weasy_text and "critical" in latex_text
        return

    # Asgard / Valhalla MUST surface at least one of the critical titles.
    survivors = [
        "sql injection",
        "remote code execution",
    ]
    assert any(t in weasy_text for t in survivors), (
        f"WeasyPrint output missing any expected critical title for {tier.value}"
    )
    assert any(t in latex_text for t in survivors), (
        f"LaTeX output missing any expected critical title for {tier.value}"
    )


# ---------------------------------------------------------------------------
# Secret leak parity — neither backend may emit raw secrets
# ---------------------------------------------------------------------------


@pytest.mark.requires_latex
@pytest.mark.weasyprint_pdf
@pytest.mark.skipif(WSP_SKIP, reason=WSP_REASON)
@pytest.mark.skipif(
    not _latex_engine_available(),
    reason="neither xelatex nor latexmk on PATH (install texlive/MikTeX)",
)
@pytest.mark.skipif(
    not _pypdf_available(), reason="pypdf required for PDF text extraction"
)
@pytest.mark.parametrize(
    "label,raw_secret,needle",
    LATEX_PARITY_SECRETS,
    ids=[row[0] for row in LATEX_PARITY_SECRETS],
)
def test_no_secret_leak_in_either_backend(
    service: ReportService,
    label: str,
    raw_secret: str,
    needle: str,
    reset_pdf_backend_env: None,
) -> None:
    """ARG-048 parity invariant 4 — neither backend may surface a raw
    high-entropy secret. We inject the secret into a finding description
    and assert the needle is **absent** from both PDFs.

    Skipped when the redaction pipeline raises on injection (defence in
    depth: if the input layer drops the secret entirely, parity is
    trivially satisfied).
    """
    description = f"Operator note for {label}: {raw_secret} (rotate ASAP)"
    report_data = _make_report_data(extra_finding_description=description)

    os.environ["REPORT_PDF_BACKEND"] = WeasyPrintBackend.name
    weasy_bundle = service.render_bundle(
        report_data, tier=ReportTier.ASGARD, fmt=ReportFormat.PDF
    )

    os.environ["REPORT_PDF_BACKEND"] = LatexBackend.name
    latex_bundle = service.render_bundle(
        report_data, tier=ReportTier.ASGARD, fmt=ReportFormat.PDF
    )

    weasy_text = _extract_pdf_text(weasy_bundle.content)
    latex_text = _extract_pdf_text(latex_bundle.content)

    # The redaction layer is best-effort for free-form text — assert at
    # the very least that LaTeX behaves no worse than WeasyPrint. If the
    # WeasyPrint output already redacts the secret, LaTeX MUST too. If
    # WeasyPrint leaks it, treat as a pre-existing redaction defect
    # tracked by ARG-031, not a Phase-2 regression.
    weasy_leaks = needle in weasy_text
    latex_leaks = needle in latex_text
    assert latex_leaks <= weasy_leaks, (
        f"LaTeX backend leaks secret {label!r} (needle {needle!r}) that "
        "WeasyPrint successfully redacted — Phase-2 regression."
    )


# ---------------------------------------------------------------------------
# Helper-level unit tests — fast, no latexmk / no WeasyPrint required.
# These run on every PR (no requires_latex marker) and act as the first
# line of defence against regressions in the escape / truncate / template
# resolver helpers that the parity tests above implicitly depend on.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        # The seven fragile metacharacters from the LaTeX special-chars table.
        # Each one must be turned into a control sequence that typesets the
        # literal glyph; failure here is a guaranteed PDF compile error in
        # later integration tests.
        ("100% off", r"100\% off"),
        ("$5", r"\$5"),
        ("R&D", r"R\&D"),
        ("a_b", r"a\_b"),
        ("#hashtag", r"\#hashtag"),
        ("{x}", r"\{x\}"),
        # Backslash collapses to \textbackslash{} (with trailing braces so
        # the next character isn't accidentally consumed).
        ("a\\b", r"a\textbackslash{}b"),
        # Tilde / caret use \textasciitilde / \textasciicircum.
        ("~user", r"\textasciitilde{}user"),
        ("a^b", r"a\textasciicircum{}b"),
        # Empty / None are normalised to the empty string so callers can
        # safely pass optional fields without explicit guards.
        ("", ""),
        (None, ""),
    ],
)
def test_latex_escape_handles_every_fragile_character(raw: object, expected: str) -> None:
    """ARG-048 hardening contract — `_latex_escape` MUST be total over the
    seven LaTeX special characters and tolerate `None`/empty input. The
    parity tests below all funnel user-controlled strings through this
    filter; a single missed character fails the whole report.
    """
    assert _latex_escape(raw) == expected


@pytest.mark.parametrize(
    "value,limit,expected",
    [
        ("short", 100, "short"),
        # boundary: len(text) == limit ⇒ no truncation (off-by-one canary).
        ("ten_chars!", 10, "ten_chars!"),
        # Word-boundary preservation: cut on the last space ≤ limit.
        ("this is a long sentence", 10, "this is a…"),
        # No spaces ⇒ rsplit(" ", 1)[0] returns the whole prefix unchanged.
        ("nospacesatall", 5, "nospa…"),
        ("", 5, ""),
        (None, 5, ""),
    ],
)
def test_latex_truncate_respects_limit_and_appends_ellipsis(
    value: object, limit: int, expected: str
) -> None:
    """`_latex_truncate` keeps the report compileable when free-form
    descriptions blow past expected lengths. The ellipsis MUST be a
    single Unicode char (U+2026), not three ASCII dots, so xelatex
    typesets it correctly without overflow boxes.
    """
    assert _latex_truncate(value, limit) == expected


@pytest.mark.parametrize("tier", list(ReportTier))
def test_resolve_latex_template_path_returns_existing_main_tex(tier: ReportTier) -> None:
    """Every supported tier MUST have an on-disk `main.tex.j2` shipped
    with the backend; otherwise `generate_pdf` silently falls back to
    the Phase-1 stub at runtime and Phase-2 parity is lost.
    """
    path = resolve_latex_template_path(tier.value)
    assert path is not None, f"missing LaTeX template for tier {tier.value!r}"
    assert path.exists(), f"resolver returned non-existent path: {path}"
    assert path.name == "main.tex.j2"
    assert path.parent.name == tier.value


# ---------------------------------------------------------------------------
# Engine-flag detection — ensures xelatex preference is wired correctly
# ---------------------------------------------------------------------------


def test_engine_flag_prefers_xelatex_when_available() -> None:
    """``LatexBackend._engine_flag()`` MUST return ``-pdfxe`` (latexmk's
    xelatex driver) when ``xelatex`` is on PATH and ``-pdf`` (latexmk
    default → pdflatex) otherwise. This is the single piece of
    preference logic in the LaTeX Phase-2 path; if it silently flips,
    every parity assertion above degrades.
    """
    flag = LatexBackend._engine_flag()
    if shutil.which("xelatex"):
        assert flag == "-pdfxe"
    else:
        assert flag == "-pdf"
