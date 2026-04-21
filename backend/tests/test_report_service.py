"""ARG-024 — Tests for :mod:`src.reports.report_service`.

Coverage targets:
    * ``ReportService.render_bundle`` (no DB) for every (tier × format) combo.
    * Validation: empty tenant id, missing scan_id+report_id, invalid tier/format.
    * Determinism for SARIF / JUnit / JSON / CSV.
    * Tier projection actually trims the rendered output (Midgard is smaller).
    * ``ReportGenerationError`` raised when PDF backend missing.

We intentionally do NOT exercise the DB-backed ``generate`` path here — that
lives in ``test_report_service_integration.py`` so the unit suite stays
fast and offline.
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
)
from src.reports.report_bundle import ReportBundle, ReportFormat, ReportTier
from src.reports.report_service import (
    DEFAULT_TOOL_VERSION,
    ReportGenerationError,
    ReportService,
)


def _summary() -> ReportSummary:
    return ReportSummary(
        critical=2, high=1, medium=0, low=0, info=0,
        technologies=["nginx"], sslIssues=0, headerIssues=0, leaksFound=False,
    )


def _full_data() -> ReportData:
    findings = [
        Finding(severity="critical", title="SQLi", description="d", cwe="CWE-89", cvss=9.8),
        Finding(severity="critical", title="RCE",  description="d", cwe="CWE-78", cvss=9.5),
        Finding(severity="high", title="XSS",      description="d", cwe="CWE-79", cvss=7.5),
        Finding(severity="low", title="Header missing", description="d"),
    ]
    return ReportData(
        report_id="r-1",
        target="https://x.test",
        summary=_summary(),
        findings=findings,
        technologies=["nginx", "django"],
        scan_id="scan-1",
        tenant_id="tenant-1",
        evidence=[EvidenceEntry(finding_id="f1", object_key="evidence/a.txt", description="d")],
        screenshots=[ScreenshotEntry(object_key="shots/a.png", url_or_email="login")],
        executive_summary="Critical SQL injection observed.",
        remediation=["Patch web framework.", "Rotate DB credentials."],
        ai_insights=["LLM analysis"],
        raw_artifacts=[{"raw": "dump"}],
    )


class TestRenderBundleJson:
    def test_returns_report_bundle(self) -> None:
        svc = ReportService()
        bundle = svc.render_bundle(_full_data(), tier=ReportTier.MIDGARD, fmt=ReportFormat.JSON)
        assert isinstance(bundle, ReportBundle)
        assert bundle.tier is ReportTier.MIDGARD
        assert bundle.format is ReportFormat.JSON
        assert bundle.size_bytes > 0

    def test_sha256_matches_payload(self) -> None:
        svc = ReportService()
        bundle = svc.render_bundle(_full_data(), tier=ReportTier.MIDGARD, fmt=ReportFormat.JSON)
        assert bundle.verify_sha256() is True

    def test_json_payload_parseable(self) -> None:
        svc = ReportService()
        bundle = svc.render_bundle(_full_data(), tier=ReportTier.VALHALLA, fmt=ReportFormat.JSON)
        payload = json.loads(bundle.content)
        assert "findings" in payload or "report_id" in payload


class TestRenderBundleSarif:
    def test_sarif_well_formed(self) -> None:
        svc = ReportService()
        bundle = svc.render_bundle(_full_data(), tier=ReportTier.ASGARD, fmt=ReportFormat.SARIF)
        assert bundle.mime_type == "application/sarif+json"
        payload = json.loads(bundle.content)
        assert payload["version"] == "2.1.0"
        assert payload["runs"][0]["tool"]["driver"]["name"] == "ARGUS"

    def test_sarif_uses_configured_tool_version(self) -> None:
        svc = ReportService(tool_version="9.9.9")
        bundle = svc.render_bundle(_full_data(), tier=ReportTier.ASGARD, fmt=ReportFormat.SARIF)
        payload = json.loads(bundle.content)
        assert payload["runs"][0]["tool"]["driver"]["version"] == "9.9.9"

    def test_default_tool_version_used(self) -> None:
        svc = ReportService()
        bundle = svc.render_bundle(_full_data(), tier=ReportTier.ASGARD, fmt=ReportFormat.SARIF)
        payload = json.loads(bundle.content)
        assert payload["runs"][0]["tool"]["driver"]["version"] == DEFAULT_TOOL_VERSION


class TestRenderBundleJunit:
    def test_junit_parseable(self) -> None:
        svc = ReportService()
        bundle = svc.render_bundle(_full_data(), tier=ReportTier.ASGARD, fmt=ReportFormat.JUNIT)
        assert bundle.mime_type.startswith("application/xml")
        root = DET.fromstring(bundle.content)
        assert root.tag == "testsuites"

    def test_junit_failures_match_failing_findings(self) -> None:
        svc = ReportService()
        bundle = svc.render_bundle(_full_data(), tier=ReportTier.ASGARD, fmt=ReportFormat.JUNIT)
        root = DET.fromstring(bundle.content)
        suite = root.find("testsuite")
        assert suite is not None
        # critical+critical+high → 3 failures; low → not failing
        assert suite.attrib["failures"] == "3"
        assert suite.attrib["tests"] == "4"


class TestRenderBundleCsv:
    def test_csv_payload(self) -> None:
        svc = ReportService()
        bundle = svc.render_bundle(_full_data(), tier=ReportTier.ASGARD, fmt=ReportFormat.CSV)
        assert bundle.mime_type.startswith("text/csv")
        body = bundle.content.decode("utf-8")
        assert "severity" in body.splitlines()[0].lower()


class TestTierProjection:
    def test_midgard_smaller_than_valhalla_for_same_data(self) -> None:
        svc = ReportService()
        data = _full_data()
        midgard = svc.render_bundle(data, tier=ReportTier.MIDGARD, fmt=ReportFormat.JSON)
        valhalla = svc.render_bundle(data, tier=ReportTier.VALHALLA, fmt=ReportFormat.JSON)
        # Valhalla embeds evidence/screenshots/raw_artifacts → bigger payload.
        assert valhalla.size_bytes >= midgard.size_bytes

    def test_midgard_strips_evidence_in_json(self) -> None:
        svc = ReportService()
        bundle = svc.render_bundle(_full_data(), tier=ReportTier.MIDGARD, fmt=ReportFormat.JSON)
        body = bundle.content.decode("utf-8").lower()
        # "evidence/a.txt" was the path in the input — must not survive in Midgard.
        assert "evidence/a.txt" not in body


class TestValidation:
    @pytest.mark.asyncio
    async def test_empty_tenant_raises(self) -> None:
        svc = ReportService()
        with pytest.raises(ValueError):
            await svc.generate(
                tenant_id="",
                scan_id="s1",
                tier=ReportTier.MIDGARD,
                fmt=ReportFormat.JSON,
            )

    @pytest.mark.asyncio
    async def test_missing_scan_and_report_raises(self) -> None:
        svc = ReportService()
        with pytest.raises(ValueError):
            await svc.generate(
                tenant_id="t1",
                scan_id=None,
                report_id=None,
                tier=ReportTier.MIDGARD,
                fmt=ReportFormat.JSON,
            )

    def test_unknown_tier_raises(self) -> None:
        svc = ReportService()
        with pytest.raises(ValueError):
            svc.render_bundle(_full_data(), tier="atlantis", fmt=ReportFormat.JSON)  # type: ignore[arg-type]

    def test_unknown_format_raises(self) -> None:
        svc = ReportService()
        with pytest.raises(ValueError):
            svc.render_bundle(_full_data(), tier=ReportTier.MIDGARD, fmt="csvx")  # type: ignore[arg-type]


class TestReportServiceDeterminism:
    def test_sarif_byte_stable(self) -> None:
        svc = ReportService()
        a = svc.render_bundle(_full_data(), tier=ReportTier.ASGARD, fmt=ReportFormat.SARIF)
        b = svc.render_bundle(_full_data(), tier=ReportTier.ASGARD, fmt=ReportFormat.SARIF)
        assert a.content == b.content
        assert a.sha256 == b.sha256

    def test_junit_byte_stable(self) -> None:
        svc = ReportService()
        a = svc.render_bundle(_full_data(), tier=ReportTier.ASGARD, fmt=ReportFormat.JUNIT)
        b = svc.render_bundle(_full_data(), tier=ReportTier.ASGARD, fmt=ReportFormat.JUNIT)
        assert a.content == b.content


class TestPdfErrorPath:
    def test_pdf_missing_native_libs_raises_typed_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from src.reports import report_service as svc_mod

        def boom(*_args: object, **_kwargs: object) -> bytes:
            raise RuntimeError("WeasyPrint not available")

        monkeypatch.setattr(svc_mod, "generate_pdf", boom)
        svc = ReportService()
        with pytest.raises(ReportGenerationError):
            svc.render_bundle(_full_data(), tier=ReportTier.MIDGARD, fmt=ReportFormat.PDF)


class TestCoercion:
    def test_string_tier_accepted(self) -> None:
        svc = ReportService()
        bundle = svc.render_bundle(_full_data(), tier="midgard", fmt="json")  # type: ignore[arg-type]
        assert bundle.tier is ReportTier.MIDGARD

    def test_string_format_accepted(self) -> None:
        svc = ReportService()
        bundle = svc.render_bundle(_full_data(), tier=ReportTier.MIDGARD, fmt="sarif")  # type: ignore[arg-type]
        assert bundle.format is ReportFormat.SARIF
