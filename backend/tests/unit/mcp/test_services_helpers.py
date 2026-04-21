"""Unit tests for the pure helper functions in MCP service modules.

The async, DB-bound entrypoints (``enqueue_scan``, ``list_findings``,
``request_report_generation`` …) are exercised end-to-end in the MCP
integration suite where a real PostgreSQL is available. Here we focus on
the deterministic, dependency-free helpers that perform shape coercion,
status mapping, and metadata extraction — these run on every tool call
and are the highest-leverage surface for regressions.

Coverage scope:

* ``scan_service`` — status / profile / scope coercion + ISO-8601 parsing
  + dispatcher injection.
* ``finding_service`` — severity coercion + summary/detail row mapping.
* ``report_service`` — tier coercion + presigned-URL / SHA-256 / expiry
  extraction from metadata blobs.
* ``approval_service`` — decision-to-status mapping + ``StoredApproval``
  ↔ ``ApprovalSummary`` round-trip.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest

from src.mcp.schemas.finding import Severity
from src.mcp.schemas.report import ReportFormat, ReportTier
from src.mcp.schemas.scan import ScanProfile, ScanScopeInput, ScanStatus
from src.mcp.services import (
    approval_service,
    finding_service,
    report_service,
    scan_service,
)


@dataclass
class _FindingRow:
    """Stand-in for ``src.db.models.Finding`` covering the fields read."""

    id: str
    scan_id: str = "scan-12345678"
    severity: str | None = "high"
    title: str | None = "SQL Injection"
    description: str | None = "Description"
    cwe: str | None = "CWE-89"
    cvss: float | None = 8.5
    owasp_category: str | None = "A03"
    confidence: str | None = "confirmed"
    evidence_type: str | None = "response"
    proof_of_concept: dict[str, Any] | None = None
    evidence_refs: list[Any] | None = None
    reproducible_steps: str | None = "Steps"
    false_positive: bool = False
    false_positive_reason: str | None = None
    created_at: datetime | None = None


class TestScanServiceHelpers:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (None, ScanStatus.PENDING),
            ("queued", ScanStatus.PENDING),
            ("init", ScanStatus.PENDING),
            ("running", ScanStatus.RUNNING),
            ("in_progress", ScanStatus.RUNNING),
            ("completed", ScanStatus.COMPLETED),
            ("done", ScanStatus.COMPLETED),
            ("failed", ScanStatus.FAILED),
            ("errored", ScanStatus.FAILED),
            ("cancelled", ScanStatus.CANCELLED),
            ("canceled", ScanStatus.CANCELLED),
            ("PENDING", ScanStatus.PENDING),
            ("  Running  ", ScanStatus.RUNNING),
        ],
    )
    def test_coerce_scan_status_known_values(
        self, raw: str | None, expected: ScanStatus
    ) -> None:
        assert scan_service._coerce_scan_status(raw) is expected

    def test_coerce_scan_status_unknown_falls_back_to_running(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            assert scan_service._coerce_scan_status("frobbed") is ScanStatus.RUNNING
        assert any("mcp.scan.unknown_status" in rec.message for rec in caplog.records)

    def test_profile_to_scan_mode(self) -> None:
        assert scan_service._profile_to_scan_mode(ScanProfile.QUICK) == "quick"
        assert scan_service._profile_to_scan_mode(ScanProfile.DEEP) == "deep"

    def test_scope_to_options_default(self) -> None:
        scope = ScanScopeInput()
        result = scan_service._scope_to_options(scope)
        assert result == {
            "scope": {
                "include_subdomains": False,
                "max_depth": 3,
                "follow_redirects": True,
            }
        }

    def test_scope_to_options_custom(self) -> None:
        scope = ScanScopeInput(
            include_subdomains=True, max_depth=7, follow_redirects=False
        )
        assert scan_service._scope_to_options(scope) == {
            "scope": {
                "include_subdomains": True,
                "max_depth": 7,
                "follow_redirects": False,
            }
        }

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (
                "2026-04-19T12:34:56Z",
                datetime(2026, 4, 19, 12, 34, 56, tzinfo=timezone.utc),
            ),
            (
                "2026-04-19T12:34:56+00:00",
                datetime(2026, 4, 19, 12, 34, 56, tzinfo=timezone.utc),
            ),
            (
                "2026-04-19T12:34:56",
                datetime(2026, 4, 19, 12, 34, 56, tzinfo=timezone.utc),
            ),
        ],
    )
    def test_parse_iso_valid(self, value: str, expected: datetime) -> None:
        assert scan_service._parse_iso(value) == expected

    def test_parse_iso_invalid(self) -> None:
        assert scan_service._parse_iso("not-a-date") is None

    def test_set_scan_dispatcher_round_trip(self) -> None:
        captured: list[str] = []

        async def _fake(scan_id, tenant_id, target, options) -> None:
            captured.append(scan_id)

        try:
            scan_service.set_scan_dispatcher(_fake)
            assert scan_service._resolve_dispatcher() is _fake
        finally:
            scan_service.set_scan_dispatcher(None)
        assert (
            scan_service._resolve_dispatcher() is scan_service._default_celery_dispatch
        )


class TestFindingServiceHelpers:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (None, Severity.INFO),
            ("info", Severity.INFO),
            ("low", Severity.LOW),
            ("medium", Severity.MEDIUM),
            ("high", Severity.HIGH),
            ("critical", Severity.CRITICAL),
            ("HIGH", Severity.HIGH),
            ("  critical  ", Severity.CRITICAL),
        ],
    )
    def test_coerce_severity(self, raw: str | None, expected: Severity) -> None:
        assert finding_service._coerce_severity(raw) is expected

    def test_coerce_severity_unknown_falls_back_to_info(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            assert finding_service._coerce_severity("frob") is Severity.INFO
        assert any(
            "mcp.finding.unknown_severity" in rec.message for rec in caplog.records
        )

    def test_ensure_aware_naive_to_utc(self) -> None:
        naive = datetime(2026, 4, 19, 12, 0, 0)
        aware = finding_service._ensure_aware(naive)
        assert aware == naive.replace(tzinfo=timezone.utc)

    def test_ensure_aware_already_aware(self) -> None:
        aware = datetime(2026, 4, 19, tzinfo=timezone.utc)
        assert finding_service._ensure_aware(aware) == aware

    def test_ensure_aware_none(self) -> None:
        assert finding_service._ensure_aware(None) is None

    def test_row_to_summary_truncates_title(self) -> None:
        row = _FindingRow(
            id="find-1234abcd",
            severity="high",
            title="A" * 600,
            cwe="CWE-89",
            owasp_category="A03",
            confidence="confirmed",
            false_positive=False,
            created_at=datetime(2026, 4, 19, tzinfo=timezone.utc),
        )
        summary = finding_service._row_to_summary(row)  # type: ignore[arg-type]
        assert summary.title == "A" * 500
        assert summary.severity is Severity.HIGH
        assert summary.created_at == datetime(2026, 4, 19, tzinfo=timezone.utc)

    def test_row_to_detail_caps_evidence_refs_and_descriptions(self) -> None:
        row = _FindingRow(
            id="find-1234abcd",
            severity="critical",
            title="x",
            description="y" * 9_000,
            evidence_refs=[f"ref-{i}" for i in range(80)],
            proof_of_concept={"steps": ["a", "b"]},
            reproducible_steps="z" * 9_000,
            false_positive=True,
            false_positive_reason="confirmed FP",
        )
        detail = finding_service._row_to_detail(row)  # type: ignore[arg-type]
        assert len(detail.description or "") == 8_000
        assert len(detail.reproducible_steps or "") == 8_000
        assert len(detail.evidence_refs) == 64
        assert detail.proof_of_concept == {"steps": ["a", "b"]}
        assert detail.false_positive is True

    def test_row_to_detail_handles_none_optional_fields(self) -> None:
        # ``title`` has a min_length=1 schema constraint, so we still pass a
        # 1-char value while every other optional column is None — exercising
        # the defensive ``or ""`` / ``or "likely"`` fall-throughs.
        row = _FindingRow(
            id="find-1234abcd",
            severity="info",
            title="x",
            description=None,
            cwe=None,
            cvss=None,
            owasp_category=None,
            confidence=None,
            evidence_type=None,
            proof_of_concept=None,
            evidence_refs=None,
            reproducible_steps=None,
            false_positive_reason=None,
        )
        detail = finding_service._row_to_detail(row)  # type: ignore[arg-type]
        assert detail.description is None
        assert detail.reproducible_steps is None
        assert detail.evidence_refs == ()
        assert detail.confidence == "likely"


class TestReportServiceHelpers:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (None, ReportTier.MIDGARD),
            ("midgard", ReportTier.MIDGARD),
            ("asgard", ReportTier.ASGARD),
            ("valhalla", ReportTier.VALHALLA),
            ("VALHALLA", ReportTier.VALHALLA),
            ("  Asgard  ", ReportTier.ASGARD),
        ],
    )
    def test_coerce_tier(self, raw: str | None, expected: ReportTier) -> None:
        assert report_service._coerce_tier(raw) is expected

    def test_coerce_tier_unknown_falls_back(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING"):
            assert report_service._coerce_tier("ouroboros") is ReportTier.MIDGARD
        assert any("mcp.report.unknown_tier" in rec.message for rec in caplog.records)

    def test_extract_sha256_normalises_case(self) -> None:
        meta = {
            "artifacts": {
                "pdf": {"sha256": "ABCDEF" + "0" * 58},
            }
        }
        assert report_service._extract_sha256(meta, ReportFormat.PDF) == (
            "abcdef" + "0" * 58
        )

    def test_extract_sha256_invalid_length(self) -> None:
        meta = {"artifacts": {"pdf": {"sha256": "abc"}}}
        assert report_service._extract_sha256(meta, ReportFormat.PDF) is None

    def test_extract_sha256_missing_bucket(self) -> None:
        meta: dict[str, Any] = {"artifacts": {}}
        assert report_service._extract_sha256(meta, ReportFormat.PDF) is None

    def test_extract_sha256_no_artifacts(self) -> None:
        assert report_service._extract_sha256({}, ReportFormat.PDF) is None

    def test_extract_presigned_url_present(self) -> None:
        meta = {"artifacts": {"json": {"presigned_url": "https://x"}}}
        assert (
            report_service._extract_presigned_url(meta, ReportFormat.JSON)
            == "https://x"
        )

    def test_extract_presigned_url_empty_string(self) -> None:
        meta = {"artifacts": {"json": {"presigned_url": ""}}}
        assert report_service._extract_presigned_url(meta, ReportFormat.JSON) is None

    def test_extract_expiry_z_suffix(self) -> None:
        meta = {"artifacts": {"json": {"expires_at": "2026-04-19T12:34:56Z"}}}
        result = report_service._extract_expiry(meta, ReportFormat.JSON)
        assert result == datetime(2026, 4, 19, 12, 34, 56, tzinfo=timezone.utc)

    def test_extract_expiry_invalid(self) -> None:
        meta = {"artifacts": {"json": {"expires_at": "not-a-date"}}}
        assert report_service._extract_expiry(meta, ReportFormat.JSON) is None

    def test_extract_expiry_no_value(self) -> None:
        meta = {"artifacts": {"json": {}}}
        assert report_service._extract_expiry(meta, ReportFormat.JSON) is None

    def test_ensure_aware_helpers_align(self) -> None:
        naive = datetime(2026, 4, 19, 1, 2, 3)
        assert report_service._ensure_aware(naive) == naive.replace(tzinfo=timezone.utc)
        assert report_service._ensure_aware(None) is None


class TestApprovalServiceHelpers:
    @pytest.mark.parametrize(
        ("decision", "expected"),
        [
            (approval_service.ApprovalDecisionAction.GRANT, "granted"),
            (approval_service.ApprovalDecisionAction.DENY, "denied"),
            (approval_service.ApprovalDecisionAction.REVOKE, "revoked"),
        ],
    )
    def test_decision_to_status(self, decision, expected: str) -> None:
        assert approval_service._decision_to_status(decision) == expected

    def test_row_to_summary_round_trip(self, tenant_id: str) -> None:
        row = approval_service.make_test_approval(tenant_id=tenant_id)
        summary = approval_service._row_to_summary(row)
        assert summary.request_id == row.request_id
        assert summary.tool_id == row.tool_id
        assert summary.target == row.target
        assert summary.action == row.action
        assert summary.signatures_present == 0

    def test_make_test_approval_matches_action_kind(self, tenant_id: str) -> None:
        destructive = approval_service.make_test_approval(
            tenant_id=tenant_id, action="destructive"
        )
        assert destructive.requires_dual_control is True
        normal = approval_service.make_test_approval(tenant_id=tenant_id)
        assert normal.requires_dual_control is False

    def test_set_get_approval_repository_round_trip(self) -> None:
        previous = approval_service.get_approval_repository()
        try:
            new = approval_service.InMemoryApprovalRepository()
            approval_service.set_approval_repository(new)
            assert approval_service.get_approval_repository() is new
        finally:
            approval_service.set_approval_repository(previous)
