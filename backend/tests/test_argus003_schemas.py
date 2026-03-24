"""Schema tests for ARGUS-003 (Phase 2: Core Backend).

Pydantic schemas validate correct/incorrect data.
"""

import pytest
from pydantic import ValidationError
from src.api.schemas import (
    HealthResponse,
    ReportDetailResponse,
    ReportListResponse,
    ReportSummary,
    ScanCreateRequest,
    ScanCreateResponse,
    ScanDetailResponse,
    ScanOptions,
    ScanOptionsAdvanced,
    ScanOptionsScope,
    ScanOptionsVulnerabilities,
)


class TestHealthResponse:
    """HealthResponse schema."""

    def test_valid(self) -> None:
        """Valid data passes."""
        r = HealthResponse(status="ok", version="0.1.0")
        assert r.status == "ok"
        assert r.version == "0.1.0"

    def test_version_optional(self) -> None:
        """Version can be omitted."""
        r = HealthResponse(status="ok")
        assert r.version is None


class TestScanCreateRequest:
    """ScanCreateRequest schema."""

    def test_minimal_valid(self) -> None:
        """target and email only."""
        r = ScanCreateRequest(target="https://x.com", email="u@x.com")
        assert r.target == "https://x.com"
        assert r.email == "u@x.com"
        assert r.options.scanType == "quick"

    def test_full_valid(self) -> None:
        """With options."""
        r = ScanCreateRequest(
            target="https://x.com",
            email="u@x.com",
            options=ScanOptions(scanType="deep", reportFormat="html"),
        )
        assert r.options.scanType == "deep"
        assert r.options.reportFormat == "html"

    def test_missing_target_raises(self) -> None:
        """Missing target raises ValidationError."""
        with pytest.raises(ValidationError):
            ScanCreateRequest(email="u@x.com")

    def test_missing_email_raises(self) -> None:
        """Missing email raises ValidationError."""
        with pytest.raises(ValidationError):
            ScanCreateRequest(target="https://x.com")


class TestScanCreateResponse:
    """ScanCreateResponse schema."""

    def test_valid(self) -> None:
        """Valid response."""
        r = ScanCreateResponse(
            scan_id="00000000-0000-0000-0000-000000000001",
            status="queued",
            message="OK",
        )
        assert r.scan_id
        assert r.status == "queued"
        assert r.message == "OK"

    def test_message_optional(self) -> None:
        """Message can be None."""
        r = ScanCreateResponse(scan_id="x", status="queued")
        assert r.message is None


class TestScanDetailResponse:
    """ScanDetailResponse schema."""

    def test_valid(self) -> None:
        """Valid response."""
        r = ScanDetailResponse(
            id="x",
            status="pending",
            progress=50,
            phase="scanning",
            target="https://x.com",
            created_at="2026-01-01T00:00:00Z",
        )
        assert r.progress == 50
        assert r.phase == "scanning"


class TestScanOptionsScope:
    """ScanOptionsScope — maxDepth, includeSubs, excludePatterns."""

    def test_valid_defaults(self) -> None:
        """Default values pass."""
        s = ScanOptionsScope()
        assert s.maxDepth == 3
        assert s.includeSubs is False

    def test_max_depth_in_range(self) -> None:
        """maxDepth 1–10 valid."""
        s = ScanOptionsScope(maxDepth=5)
        assert s.maxDepth == 5

    def test_max_depth_out_of_range_raises(self) -> None:
        """maxDepth < 1 or > 10 raises."""
        with pytest.raises(ValidationError):
            ScanOptionsScope(maxDepth=0)
        with pytest.raises(ValidationError):
            ScanOptionsScope(maxDepth=11)


class TestScanOptionsAdvanced:
    """ScanOptionsAdvanced — timeout, userAgent, proxy."""

    def test_timeout_in_range(self) -> None:
        """timeout 5–120 valid."""
        s = ScanOptionsAdvanced(timeout=30)
        assert s.timeout == 30

    def test_timeout_out_of_range_raises(self) -> None:
        """timeout < 5 or > 120 raises."""
        with pytest.raises(ValidationError):
            ScanOptionsAdvanced(timeout=4)
        with pytest.raises(ValidationError):
            ScanOptionsAdvanced(timeout=121)


class TestScanOptionsVulnerabilities:
    """ScanOptionsVulnerabilities — xss, sqli, etc."""

    def test_defaults(self) -> None:
        """Default vulnerability flags."""
        v = ScanOptionsVulnerabilities()
        assert v.xss is True
        assert v.sqli is True
        assert v.csrf is True
        assert v.ssrf is False


class TestReportSummary:
    """ReportSummary schema."""

    def test_valid_defaults(self) -> None:
        """Default values."""
        s = ReportSummary()
        assert s.critical == 0
        assert s.high == 0
        assert s.technologies == []

    def test_with_findings(self) -> None:
        """With severity counts."""
        s = ReportSummary(critical=1, high=2, medium=3)
        assert s.critical == 1
        assert s.high == 2
        assert s.medium == 3


class TestReportListResponse:
    """ReportListResponse schema."""

    def test_valid(self) -> None:
        """Valid response."""
        r = ReportListResponse(
            report_id="r1",
            target="https://x.com",
            summary=ReportSummary(),
        )
        assert r.report_id == "r1"
        assert r.findings == []
        assert r.technologies == []


class TestReportDetailResponse:
    """ReportDetailResponse schema."""

    def test_valid_with_optionals(self) -> None:
        """created_at and scan_id optional."""
        r = ReportDetailResponse(
            report_id="r1",
            target="https://x.com",
            summary=ReportSummary(),
            created_at=None,
            scan_id=None,
            generation_status="pending",
            tier="asgard",
            requested_formats=["pdf", "html"],
        )
        assert r.created_at is None
        assert r.scan_id is None
        assert r.generation_status == "pending"
        assert r.tier == "asgard"
        assert r.requested_formats == ["pdf", "html"]
