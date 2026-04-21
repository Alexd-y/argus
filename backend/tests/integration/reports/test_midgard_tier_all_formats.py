"""ARG-024 — Integration: ReportService Midgard tier × all six formats.

Lives at the plan-mandated path ``backend/tests/integration/reports/`` and
proves three contracts end-to-end:

1. **Multi-format coverage** — Midgard renders successfully through every
   :class:`~src.reports.report_bundle.ReportFormat`
   (HTML / PDF / JSON / CSV / SARIF / JUnit).
2. **Schema validity** — SARIF payload is SARIF v2.1.0 conformant; JUnit
   payload parses via :mod:`defusedxml`; JSON payload is valid UTF-8 JSON;
   CSV header carries the expected columns.
3. **Snapshot stability (determinism)** — JSON / CSV / SARIF / JUnit
   bytes match the golden fixtures under
   ``backend/tests/snapshots/reports/``. Refresh the goldens by setting
   ``ARGUS_SNAPSHOT_REFRESH=1``.

The DB-backed ``ReportService.generate`` path is exercised separately in
``backend/tests/test_report_service.py``; this file uses
``render_bundle`` only so it stays fast and offline.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Final

import pytest
from defusedxml import ElementTree as DET  # type: ignore[import-untyped]  # defusedxml has no upstream stubs

from src.api.schemas import Finding, ReportSummary
from src.reports.generators import (
    EvidenceEntry,
    PhaseOutputEntry,
    ReportData,
    ScreenshotEntry,
    TimelineEntry,
)
from src.reports.report_bundle import ReportFormat, ReportTier
from src.reports.report_service import (
    ReportGenerationError,
    ReportService,
)


# ---------------------------------------------------------------------------
# Snapshot directory + refresh policy
# ---------------------------------------------------------------------------


SNAPSHOT_DIR: Final[Path] = (
    Path(__file__).resolve().parents[2] / "snapshots" / "reports"
)
SNAPSHOT_REFRESH_ENV: Final[str] = "ARGUS_SNAPSHOT_REFRESH"
SNAPSHOT_TOOL_VERSION: Final[str] = "arg-024-snapshot"


def _snapshot_path(fmt: ReportFormat) -> Path:
    """Return the ``midgard_canonical.<ext>`` snapshot path for ``fmt``."""
    extension_overrides = {ReportFormat.JUNIT: "xml"}
    ext = extension_overrides.get(fmt, fmt.value)
    return SNAPSHOT_DIR / f"midgard_canonical.{ext}"


def _refresh_requested() -> bool:
    return os.environ.get(SNAPSHOT_REFRESH_ENV, "").strip() not in ("", "0", "false", "False")


# ---------------------------------------------------------------------------
# Canonical fixture — same shape used to generate the goldens
# ---------------------------------------------------------------------------


@pytest.fixture
def canonical_report_data() -> ReportData:
    """Representative Midgard input: at least one of each interesting field.

    Sized to exercise the Midgard top-N cap (12 findings → cap at 10) and
    every field the tier classifier strips so snapshot bytes prove the
    redaction contract too.
    """
    summary = ReportSummary(
        critical=2,
        high=2,
        medium=2,
        low=2,
        info=2,
        technologies=["nginx", "django"],
        sslIssues=1,
        headerIssues=2,
        leaksFound=False,
    )
    findings = [
        Finding(
            severity="critical",
            title="SQL Injection in /api/users",
            description="UNION-based SQLi via id parameter.",
            cwe="CWE-89",
            cvss=9.8,
            owasp_category="A03",
            evidence_refs=["s3://argus-evidence/sqli-dump"],
        ),
        Finding(
            severity="critical",
            title="Remote Code Execution in /upload",
            description="Unrestricted file upload + LFI chain.",
            cwe="CWE-78",
            cvss=9.5,
        ),
        Finding(
            severity="high",
            title="Reflected XSS in search",
            description="`q` echoed unescaped.",
            cwe="CWE-79",
            cvss=7.5,
            owasp_category="A03",
        ),
        Finding(
            severity="high",
            title="Server-Side Request Forgery",
            description="Internal metadata endpoint reachable.",
            cwe="CWE-918",
            cvss=8.1,
        ),
        Finding(
            severity="medium",
            title="Missing security headers",
            description="No CSP / HSTS / X-Frame-Options.",
            cwe="CWE-693",
        ),
        Finding(
            severity="medium",
            title="Outdated jQuery",
            description="jQuery 1.x with known prototype-pollution.",
            cwe="CWE-1104",
            cvss=6.1,
        ),
        Finding(
            severity="low",
            title="Server banner exposed",
            description="Server header leaks nginx/1.18.0.",
            cwe="CWE-200",
        ),
        Finding(
            severity="low",
            title="Cookie missing Secure flag",
            description="Session cookie served over HTTP.",
            cwe="CWE-614",
        ),
        Finding(
            severity="info",
            title="HTTP allowed alongside HTTPS",
            description="Plain HTTP returns 200 OK.",
        ),
        Finding(
            severity="info",
            title="Robots.txt disclosure",
            description="Discovered /admin.",
        ),
        Finding(
            severity="info",
            title="Open directory listing",
            description="/static/ shows directory index.",
        ),
        Finding(
            severity="info",
            title="OpenAPI 3.0 surface mapped",
            description="Found 47 endpoints.",
        ),
    ]
    return ReportData(
        report_id="r-int-midgard-1",
        target="https://app.example.test",
        summary=summary,
        findings=findings,
        technologies=["nginx", "django"],
        scan_id="scan-int-midgard-1",
        tenant_id="tenant-int-midgard-1",
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
                created_at="2026-04-19T10:00:00Z",
            )
        ],
        phase_outputs=[PhaseOutputEntry(phase="recon", output_data={"k": "v"})],
        executive_summary="Critical SQL/RCE issues observed; remediate immediately.",
        remediation=["Patch ORM.", "Disable unrestricted upload."],
        ai_insights=["LLM exec summary"],
        raw_artifacts=[{"raw": "recon dump"}],
        hibp_pwned_password_summary={"pwned_count": 12},
        created_at="2026-04-19T10:00:00Z",
    )


@pytest.fixture
def service() -> ReportService:
    return ReportService(tool_version=SNAPSHOT_TOOL_VERSION)


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
def test_midgard_renders_machine_format(
    service: ReportService,
    canonical_report_data: ReportData,
    fmt: ReportFormat,
) -> None:
    """Every machine-readable format succeeds and round-trips its SHA-256."""
    bundle = service.render_bundle(canonical_report_data, tier=ReportTier.MIDGARD, fmt=fmt)
    assert bundle.tier is ReportTier.MIDGARD
    assert bundle.format is fmt
    assert bundle.size_bytes > 0
    assert bundle.size_bytes == len(bundle.content)
    assert bundle.verify_sha256()


def test_midgard_html_renders(
    service: ReportService, canonical_report_data: ReportData
) -> None:
    bundle = service.render_bundle(
        canonical_report_data, tier=ReportTier.MIDGARD, fmt=ReportFormat.HTML
    )
    assert bundle.size_bytes > 0
    body = bundle.content.decode("utf-8", errors="replace").lower()
    assert "<html" in body or "<!doctype html" in body


def test_midgard_pdf_renders_or_skips(
    service: ReportService, canonical_report_data: ReportData
) -> None:
    """PDF requires WeasyPrint native libs — skip cleanly when absent."""
    try:
        bundle = service.render_bundle(
            canonical_report_data, tier=ReportTier.MIDGARD, fmt=ReportFormat.PDF
        )
    except ReportGenerationError:
        pytest.skip("WeasyPrint native libraries not available on this host")
    assert bundle.size_bytes > 0
    assert bundle.content[:5] == b"%PDF-"


# ---------------------------------------------------------------------------
# Schema validity contracts
# ---------------------------------------------------------------------------


def test_sarif_payload_is_valid_v2_1_0(
    service: ReportService, canonical_report_data: ReportData
) -> None:
    bundle = service.render_bundle(
        canonical_report_data, tier=ReportTier.MIDGARD, fmt=ReportFormat.SARIF
    )
    payload = json.loads(bundle.content)
    assert payload["version"] == "2.1.0"
    assert payload["$schema"].endswith("sarif-2.1.0.json")
    runs = payload["runs"]
    assert len(runs) == 1
    run = runs[0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "ARGUS"
    assert driver["version"] == SNAPSHOT_TOOL_VERSION
    # Top-N applied: at most ``MIDGARD_TOP_FINDINGS`` (10) findings on Midgard.
    assert len(run["results"]) <= 10
    for r in run["results"]:
        assert "ruleId" in r
        assert "level" in r
        assert "message" in r and "text" in r["message"]


def test_junit_payload_is_valid_xml(
    service: ReportService, canonical_report_data: ReportData
) -> None:
    bundle = service.render_bundle(
        canonical_report_data, tier=ReportTier.MIDGARD, fmt=ReportFormat.JUNIT
    )
    root = DET.fromstring(bundle.content)
    assert root.tag == "testsuites"
    suite = root.find("testsuite")
    assert suite is not None
    assert int(suite.attrib["tests"]) >= 1
    failures = int(suite.attrib["failures"])
    # Fixture has 2 critical + 2 high + 2 medium → ≥6 failures pre-cap, but
    # Midgard caps to top-10 priority order (all 6 fit) → exactly 6.
    assert failures >= 6


def test_csv_payload_has_canonical_columns(
    service: ReportService, canonical_report_data: ReportData
) -> None:
    bundle = service.render_bundle(
        canonical_report_data, tier=ReportTier.MIDGARD, fmt=ReportFormat.CSV
    )
    text = bundle.content.decode("utf-8")
    header = text.splitlines()[0].lower()
    assert "severity" in header
    assert "title" in header


def test_json_payload_is_valid(
    service: ReportService, canonical_report_data: ReportData
) -> None:
    bundle = service.render_bundle(
        canonical_report_data, tier=ReportTier.MIDGARD, fmt=ReportFormat.JSON
    )
    payload = json.loads(bundle.content)
    assert isinstance(payload, dict)


# ---------------------------------------------------------------------------
# Determinism (byte-equal across consecutive runs)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fmt",
    [ReportFormat.JSON, ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.JUNIT],
)
def test_byte_identical_across_runs(
    service: ReportService,
    canonical_report_data: ReportData,
    fmt: ReportFormat,
) -> None:
    a = service.render_bundle(canonical_report_data, tier=ReportTier.MIDGARD, fmt=fmt)
    b = service.render_bundle(canonical_report_data, tier=ReportTier.MIDGARD, fmt=fmt)
    assert a.content == b.content
    assert a.sha256 == b.sha256


# ---------------------------------------------------------------------------
# Tier-isolation contracts (Midgard NEVER leaks evidence/screenshots/raw)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fmt",
    [ReportFormat.JSON, ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.JUNIT],
)
def test_midgard_strips_evidence_from_machine_outputs(
    service: ReportService,
    canonical_report_data: ReportData,
    fmt: ReportFormat,
) -> None:
    """Sensitive paths from input ReportData MUST NOT appear in Midgard output."""
    bundle = service.render_bundle(canonical_report_data, tier=ReportTier.MIDGARD, fmt=fmt)
    body = bundle.content.decode("utf-8", errors="replace").lower()
    # The two strongest signals from the fixture:
    assert "evidence/sqli/dump.txt" not in body
    assert "screenshots/login.png" not in body
    assert "raw recon dump" not in body


# ---------------------------------------------------------------------------
# Snapshot byte-equality (golden files under tests/snapshots/reports/)
# ---------------------------------------------------------------------------


def _refresh_or_assert(actual: bytes, snapshot: Path) -> None:
    """Either refresh the snapshot (when ``ARGUS_SNAPSHOT_REFRESH`` is set) or assert equality."""
    if _refresh_requested() or not snapshot.exists():
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        snapshot.write_bytes(actual)
        return
    expected = snapshot.read_bytes()
    if actual != expected:  # pragma: no cover — intentional bytewise compare
        msg_lines = [
            f"Snapshot mismatch for {snapshot.name}.",
            f"Expected size: {len(expected)} bytes; actual: {len(actual)} bytes.",
            f"Refresh with `${SNAPSHOT_REFRESH_ENV}=1 pytest {snapshot.name}` if intended.",
        ]
        # First-divergence pointer aids debugging without dumping the whole blob.
        for i, (e, a) in enumerate(zip(expected, actual, strict=False)):
            if e != a:
                msg_lines.append(
                    f"First diverging byte at offset {i}: expected 0x{e:02x}, actual 0x{a:02x}"
                )
                msg_lines.append(
                    f"Context: expected={expected[max(0, i - 32) : i + 32]!r}"
                )
                msg_lines.append(
                    f"         actual=  {actual[max(0, i - 32) : i + 32]!r}"
                )
                break
        raise AssertionError("\n".join(msg_lines))


@pytest.fixture
def snapshot_dir() -> Iterator[Path]:
    SNAPSHOT_DIR.mkdir(parents=True, exist_ok=True)
    yield SNAPSHOT_DIR


@pytest.mark.parametrize(
    "fmt",
    [ReportFormat.JSON, ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.JUNIT],
)
def test_midgard_snapshot_bytes_stable(
    service: ReportService,
    canonical_report_data: ReportData,
    snapshot_dir: Path,
    fmt: ReportFormat,
) -> None:
    """Byte-equality against the canonical Midgard golden file for ``fmt``."""
    bundle = service.render_bundle(canonical_report_data, tier=ReportTier.MIDGARD, fmt=fmt)
    snapshot = _snapshot_path(fmt)
    _refresh_or_assert(bundle.content, snapshot)


# ---------------------------------------------------------------------------
# Tier consistency (same fixture across every tier renders all formats)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "tier",
    [ReportTier.MIDGARD, ReportTier.ASGARD, ReportTier.VALHALLA],
)
@pytest.mark.parametrize(
    "fmt",
    [ReportFormat.JSON, ReportFormat.CSV, ReportFormat.SARIF, ReportFormat.JUNIT],
)
def test_every_tier_renders_every_machine_format(
    service: ReportService,
    canonical_report_data: ReportData,
    tier: ReportTier,
    fmt: ReportFormat,
) -> None:
    bundle = service.render_bundle(canonical_report_data, tier=tier, fmt=fmt)
    assert bundle.tier is tier
    assert bundle.format is fmt
    assert bundle.size_bytes > 0
    assert bundle.verify_sha256()


# ---------------------------------------------------------------------------
# Header / metadata consistency
# ---------------------------------------------------------------------------


def test_metadata_consistency_across_formats(
    service: ReportService, canonical_report_data: ReportData
) -> None:
    """Every Midgard format yields a distinct payload (distinct SHA) but consistent envelope."""
    seen: set[str] = set()
    formats = (
        ReportFormat.JSON,
        ReportFormat.CSV,
        ReportFormat.SARIF,
        ReportFormat.JUNIT,
        ReportFormat.HTML,
    )
    for fmt in formats:
        bundle = service.render_bundle(
            canonical_report_data, tier=ReportTier.MIDGARD, fmt=fmt
        )
        assert bundle.tier is ReportTier.MIDGARD
        assert bundle.format is fmt
        assert bundle.mime_type
        assert bundle.size_bytes == len(bundle.content)
        seen.add(bundle.sha256)
    assert len(seen) == len(formats)
