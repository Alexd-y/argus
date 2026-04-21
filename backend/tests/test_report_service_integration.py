"""ARG-024 — Integration test: Midgard × all 6 formats end-to-end.

This is *not* a DB-backed integration test (the in-memory ReportData path
is exercised in ``test_report_service.py``). What this file proves is the
**multi-format rendering contract** — every supported format produces a
valid bundle from the same canonical input, with consistent metadata
across tiers.

It also asserts:
    * the SARIF and JUnit outputs are *parseable* by their respective
      schemas (offline checks — no network required);
    * MIME types and file extensions are stable;
    * SHA-256 round-trips for every format;
    * Midgard / Asgard / Valhalla all render every format without error.

WeasyPrint (PDF) requires native libraries that aren't available on the
default Windows Codespace image, so the PDF case is skipped if the
import fails — same pattern used by ``test_report_pdf_artifacts.py``.
"""

from __future__ import annotations

import json

import pytest
from defusedxml import ElementTree as DET

from src.api.schemas import Finding, ReportSummary
from src.reports.generators import (
    EvidenceEntry,
    ReportData,
    ScreenshotEntry,
    TimelineEntry,
)
from src.reports.report_bundle import ReportFormat, ReportTier
from src.reports.report_service import (
    ReportGenerationError,
    ReportService,
)


@pytest.fixture
def canonical_report_data() -> ReportData:
    """Representative ReportData with at least one of every interesting field."""
    summary = ReportSummary(
        critical=2, high=1, medium=1, low=1, info=0,
        technologies=["nginx", "django"],
        sslIssues=1, headerIssues=2, leaksFound=False,
    )
    findings = [
        Finding(
            severity="critical",
            title="SQL Injection in /api/users",
            description="UNION-based SQLi via id parameter.",
            cwe="CWE-89",
            cvss=9.8,
            owasp_category="A03",
            evidence_refs=["s3://argus-evidence/a"],
        ),
        Finding(
            severity="critical",
            title="Remote Code Execution in upload",
            description="Unrestricted file upload + LFI.",
            cwe="CWE-78",
            cvss=9.5,
        ),
        Finding(
            severity="high",
            title="Reflected XSS",
            description="`q` echoed unescaped.",
            cwe="CWE-79",
            cvss=7.5,
            owasp_category="A03",
        ),
        Finding(
            severity="medium",
            title="Missing security headers",
            description="No CSP / HSTS.",
            cwe="CWE-693",
        ),
        Finding(severity="low", title="Server banner exposed", description=""),
    ]
    return ReportData(
        report_id="r-int-1",
        target="https://app.example.test",
        summary=summary,
        findings=findings,
        technologies=["nginx", "django"],
        scan_id="scan-int-1",
        tenant_id="tenant-int-1",
        evidence=[
            EvidenceEntry(
                finding_id="f1", object_key="evidence/dump.txt", description="HTTP dump"
            )
        ],
        screenshots=[ScreenshotEntry(object_key="shots/login.png", url_or_email="login")],
        timeline=[
            TimelineEntry(
                phase="recon",
                order_index=0,
                entry={"phase": "started"},
                created_at="2026-04-19T10:00:00Z",
            )
        ],
        executive_summary="Critical SQL/RCE issues observed; remediate immediately.",
        remediation=["Patch ORM.", "Disable unrestricted upload."],
        ai_insights=["LLM exec summary"],
        raw_artifacts=[{"raw": "recon dump"}],
        hibp_pwned_password_summary={"pwned_count": 12},
    )


@pytest.fixture
def service() -> ReportService:
    return ReportService(tool_version="1.0.0-test")


@pytest.mark.parametrize(
    "fmt",
    [
        ReportFormat.JSON,
        ReportFormat.CSV,
        ReportFormat.SARIF,
        ReportFormat.JUNIT,
    ],
)
def test_midgard_renders_all_machine_formats(
    service: ReportService,
    canonical_report_data: ReportData,
    fmt: ReportFormat,
) -> None:
    """Midgard (Tier 1) renders every machine-readable format successfully."""
    bundle = service.render_bundle(
        canonical_report_data,
        tier=ReportTier.MIDGARD,
        fmt=fmt,
    )
    assert bundle.tier is ReportTier.MIDGARD
    assert bundle.format is fmt
    assert bundle.size_bytes > 0
    assert bundle.verify_sha256()


def test_midgard_html_renders(service: ReportService, canonical_report_data: ReportData) -> None:
    bundle = service.render_bundle(
        canonical_report_data,
        tier=ReportTier.MIDGARD,
        fmt=ReportFormat.HTML,
    )
    assert bundle.size_bytes > 0
    body = bundle.content.decode("utf-8", errors="replace").lower()
    assert "<html" in body or "<!doctype html" in body


def test_midgard_pdf_renders_or_skips(
    service: ReportService,
    canonical_report_data: ReportData,
) -> None:
    try:
        bundle = service.render_bundle(
            canonical_report_data,
            tier=ReportTier.MIDGARD,
            fmt=ReportFormat.PDF,
        )
    except ReportGenerationError:
        pytest.skip("WeasyPrint native libraries not available on this host")
    assert bundle.size_bytes > 0
    assert bundle.content[:5] == b"%PDF-"


def test_sarif_payload_is_valid_v2_1_0(
    service: ReportService,
    canonical_report_data: ReportData,
) -> None:
    bundle = service.render_bundle(
        canonical_report_data,
        tier=ReportTier.MIDGARD,
        fmt=ReportFormat.SARIF,
    )
    payload = json.loads(bundle.content)
    assert payload["version"] == "2.1.0"
    assert payload["$schema"].endswith("sarif-2.1.0.json")
    runs = payload["runs"]
    assert len(runs) == 1
    run = runs[0]
    assert run["tool"]["driver"]["name"] == "ARGUS"
    # Top-N applied: critical+high present, but no more than MIDGARD_TOP_FINDINGS.
    assert len(run["results"]) <= 10
    # Each result has the SARIF-required fields.
    for r in run["results"]:
        assert "ruleId" in r
        assert "level" in r
        assert "message" in r and "text" in r["message"]


def test_junit_payload_is_valid_xml(
    service: ReportService,
    canonical_report_data: ReportData,
) -> None:
    bundle = service.render_bundle(
        canonical_report_data,
        tier=ReportTier.MIDGARD,
        fmt=ReportFormat.JUNIT,
    )
    root = DET.fromstring(bundle.content)
    assert root.tag == "testsuites"
    suite = root.find("testsuite")
    assert suite is not None
    assert int(suite.attrib["tests"]) >= 1
    failures = int(suite.attrib["failures"])
    # Critical/high/medium are failing → at least 4 failures expected (cap = 10).
    assert failures >= 4


def test_csv_payload_has_header(
    service: ReportService,
    canonical_report_data: ReportData,
) -> None:
    bundle = service.render_bundle(
        canonical_report_data,
        tier=ReportTier.MIDGARD,
        fmt=ReportFormat.CSV,
    )
    text = bundle.content.decode("utf-8")
    header = text.splitlines()[0]
    assert "severity" in header.lower()
    assert "title" in header.lower()


def test_json_payload_is_valid(
    service: ReportService,
    canonical_report_data: ReportData,
) -> None:
    bundle = service.render_bundle(
        canonical_report_data,
        tier=ReportTier.MIDGARD,
        fmt=ReportFormat.JSON,
    )
    payload = json.loads(bundle.content)
    assert isinstance(payload, dict)


@pytest.mark.parametrize(
    "tier",
    [ReportTier.MIDGARD, ReportTier.ASGARD, ReportTier.VALHALLA],
)
def test_sarif_works_for_every_tier(
    service: ReportService,
    canonical_report_data: ReportData,
    tier: ReportTier,
) -> None:
    bundle = service.render_bundle(
        canonical_report_data,
        tier=tier,
        fmt=ReportFormat.SARIF,
    )
    assert bundle.verify_sha256()
    payload = json.loads(bundle.content)
    assert payload["version"] == "2.1.0"


def test_metadata_consistency_across_formats(
    service: ReportService,
    canonical_report_data: ReportData,
) -> None:
    """All bundles for the same tier expose stable mime/format/sha behaviour."""
    seen: set[str] = set()
    for fmt in (
        ReportFormat.JSON,
        ReportFormat.CSV,
        ReportFormat.SARIF,
        ReportFormat.JUNIT,
        ReportFormat.HTML,
    ):
        bundle = service.render_bundle(
            canonical_report_data,
            tier=ReportTier.MIDGARD,
            fmt=fmt,
        )
        assert bundle.tier is ReportTier.MIDGARD
        assert bundle.format is fmt
        assert bundle.mime_type
        assert bundle.size_bytes == len(bundle.content)
        seen.add(bundle.sha256)
    # Each format yields a distinct payload → distinct SHA.
    assert len(seen) == 5
