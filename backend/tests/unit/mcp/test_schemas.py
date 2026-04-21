"""Unit tests for MCP Pydantic schemas.

Covers:

* Strict ``extra='forbid'`` and ``StrictStr`` / ``StrictInt`` validation —
  unknown / loosely-typed fields MUST be rejected so an LLM client can never
  smuggle internal-only options through the schema.
* Bounded enum values (severity, scan profile, risk level, etc.).
* Pagination upper bounds (``limit <= 200``, ``offset <= 100_000``).
* Pattern validation for the scan ``target`` field and OWASP category ids.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.mcp.schemas.approval import (
    ApprovalDecideInput,
    ApprovalDecisionAction,
    ApprovalListInput,
)
from src.mcp.schemas.common import (
    AcknowledgementResult,
    FailureSummary,
    PaginationInput,
    ToolResultStatus,
)
from src.mcp.schemas.finding import (
    FindingFilter,
    FindingListInput,
    FindingMarkFalsePositiveInput,
    Severity,
)
from src.mcp.schemas.policy import (
    PolicyEvaluateInput,
    PolicyEvaluationOutcome,
    PolicyRiskLevel,
    ScopeVerifyInput,
)
from src.mcp.schemas.report import ReportFormat, ReportGenerateInput, ReportTier
from src.mcp.schemas.scan import (
    ScanCancelInput,
    ScanCreateInput,
    ScanProfile,
    ScanScopeInput,
    ScanStatus,
)
from src.mcp.schemas.tool_run import (
    ToolCatalogListInput,
    ToolRiskLevel,
    ToolRunStatus,
    ToolRunStatusInput,
    ToolRunTriggerInput,
)


# ---------------------------------------------------------------------------
# Common primitives
# ---------------------------------------------------------------------------


class TestPaginationInput:
    def test_defaults_within_bounds(self) -> None:
        page = PaginationInput()
        assert page.limit == 50
        assert page.offset == 0

    @pytest.mark.parametrize("limit", [1, 50, 200])
    def test_valid_limits(self, limit: int) -> None:
        page = PaginationInput(limit=limit)
        assert page.limit == limit

    @pytest.mark.parametrize("limit", [0, -1, 201, 1_000])
    def test_invalid_limits_rejected(self, limit: int) -> None:
        with pytest.raises(ValidationError):
            PaginationInput(limit=limit)

    @pytest.mark.parametrize("offset", [0, 100_000])
    def test_valid_offsets(self, offset: int) -> None:
        page = PaginationInput(offset=offset)
        assert page.offset == offset

    @pytest.mark.parametrize("offset", [-1, 100_001])
    def test_invalid_offsets_rejected(self, offset: int) -> None:
        with pytest.raises(ValidationError):
            PaginationInput(offset=offset)

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            PaginationInput(limit=1, offset=0, extra="boom")  # type: ignore[call-arg]


class TestToolResultStatus:
    def test_closed_taxonomy(self) -> None:
        assert {s.value for s in ToolResultStatus} == {
            "ok",
            "success",
            "unchanged",
            "noop",
            "queued",
            "denied",
        }


class TestFailureSummary:
    def test_minimum(self) -> None:
        summary = FailureSummary(code="mcp_validation_error")
        assert summary.code == "mcp_validation_error"
        assert summary.detail is None

    def test_detail_truncation_enforced(self) -> None:
        with pytest.raises(ValidationError):
            FailureSummary(code="x", detail="A" * 201)

    def test_extra_fields_forbidden(self) -> None:
        with pytest.raises(ValidationError):
            FailureSummary(code="x", extra="bad")  # type: ignore[call-arg]


class TestAcknowledgementResult:
    def test_default_actionable_true(self) -> None:
        ack = AcknowledgementResult(status=ToolResultStatus.OK)
        assert ack.actionable is True
        assert ack.message is None
        assert ack.audit_event_id is None

    def test_message_too_long_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AcknowledgementResult(status=ToolResultStatus.OK, message="x" * 201)


# ---------------------------------------------------------------------------
# Scan schemas
# ---------------------------------------------------------------------------


class TestScanCreateInput:
    @pytest.mark.parametrize(
        "target",
        [
            "https://example.com",
            "http://example.com:8080/path?q=1",
            "example.com",
            "sub.example.com:443",
        ],
    )
    def test_valid_targets(self, target: str) -> None:
        payload = ScanCreateInput(target=target)
        assert payload.target == target
        assert payload.profile is ScanProfile.STANDARD

    @pytest.mark.parametrize(
        "target",
        [
            "",
            "javascript:alert(1)",
            "ftp://example.com",
            "::malformed::",
            " ",
        ],
    )
    def test_invalid_targets_rejected(self, target: str) -> None:
        with pytest.raises(ValidationError):
            ScanCreateInput(target=target)

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScanCreateInput(  # type: ignore[call-arg]
                target="example.com", admin_override=True
            )

    def test_default_scope_is_safe(self) -> None:
        payload = ScanCreateInput(target="example.com")
        assert payload.scope.include_subdomains is False
        assert payload.scope.max_depth == 3
        assert payload.scope.follow_redirects is True

    def test_scope_max_depth_clamped(self) -> None:
        with pytest.raises(ValidationError):
            ScanScopeInput(max_depth=0)  # type: ignore[call-arg]
        with pytest.raises(ValidationError):
            ScanScopeInput(max_depth=11)  # type: ignore[call-arg]


class TestScanCancelInput:
    def test_short_reason_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScanCancelInput(scan_id="a" * 8, reason="abc")

    def test_long_reason_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScanCancelInput(scan_id="a" * 8, reason="x" * 201)

    def test_short_scan_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ScanCancelInput(scan_id="abc", reason="legit reason")


class TestScanStatusEnum:
    def test_taxonomy_closed(self) -> None:
        assert {s.value for s in ScanStatus} == {
            "pending",
            "running",
            "completed",
            "failed",
            "cancelled",
        }


# ---------------------------------------------------------------------------
# Finding schemas
# ---------------------------------------------------------------------------


class TestFindingFilter:
    @pytest.mark.parametrize("category", ["A01", "A02", "A09", "A10"])
    def test_valid_owasp_categories(self, category: str) -> None:
        filt = FindingFilter(owasp_category=category)
        assert filt.owasp_category == category

    @pytest.mark.parametrize("category", ["A00", "A11", "B01", "a01", "01", "AAA"])
    def test_invalid_owasp_categories_rejected(self, category: str) -> None:
        with pytest.raises(ValidationError):
            FindingFilter(owasp_category=category)

    def test_severity_enum(self) -> None:
        filt = FindingFilter(severity=Severity.HIGH)
        assert filt.severity is Severity.HIGH

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            FindingFilter(unknown="x")  # type: ignore[call-arg]


class TestFindingListInput:
    def test_default_filters_and_pagination(self) -> None:
        payload = FindingListInput(scan_id="scan-1234")
        assert payload.filters.severity is None
        assert payload.pagination.limit == 50

    def test_short_scan_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            FindingListInput(scan_id="abc")


class TestFindingMarkFalsePositive:
    def test_short_reason_rejected(self) -> None:
        with pytest.raises(ValidationError):
            FindingMarkFalsePositiveInput(finding_id="a" * 8, reason="short")

    def test_valid_reason(self) -> None:
        payload = FindingMarkFalsePositiveInput(
            finding_id="a" * 12, reason="duplicate of finding-XYZ"
        )
        assert payload.reason.startswith("duplicate")


# ---------------------------------------------------------------------------
# Approval schemas
# ---------------------------------------------------------------------------


class TestApprovalDecideInput:
    def test_grant_minimum_required_fields(self) -> None:
        payload = ApprovalDecideInput(
            request_id="req-12345",
            decision=ApprovalDecisionAction.DENY,
            justification="Suspicious request, deny.",
        )
        assert payload.decision is ApprovalDecisionAction.DENY

    def test_signature_length_bounds(self) -> None:
        with pytest.raises(ValidationError):
            ApprovalDecideInput(
                request_id="req-12345",
                decision=ApprovalDecisionAction.GRANT,
                signature_b64="A" * 50,
            )
        with pytest.raises(ValidationError):
            ApprovalDecideInput(
                request_id="req-12345",
                decision=ApprovalDecisionAction.GRANT,
                signature_b64="A" * 200,
            )


class TestApprovalListInput:
    def test_optional_filters(self) -> None:
        payload = ApprovalListInput()
        assert payload.tool_id is None
        assert payload.tenant_id is None
        assert payload.status is None

    def test_extra_field_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ApprovalListInput(unknown="x")  # type: ignore[call-arg]


# ---------------------------------------------------------------------------
# Tool catalog / run schemas
# ---------------------------------------------------------------------------


class TestToolCatalogListInput:
    def test_defaults(self) -> None:
        payload = ToolCatalogListInput()
        assert payload.category is None
        assert payload.risk_level is None
        assert payload.requires_approval is None

    def test_risk_filter(self) -> None:
        payload = ToolCatalogListInput(risk_level=ToolRiskLevel.HIGH)
        assert payload.risk_level is ToolRiskLevel.HIGH


class TestToolRunTriggerInput:
    def test_short_tool_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ToolRunTriggerInput(tool_id="a", target="example.com")

    def test_target_length_capped(self) -> None:
        with pytest.raises(ValidationError):
            ToolRunTriggerInput(
                tool_id="nuclei",
                target="x" * 3000,
            )


class TestToolRunStatusInput:
    def test_short_tool_run_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ToolRunStatusInput(tool_run_id="abc")


class TestMcpSchemasToolRunStatus:
    def test_taxonomy_closed(self) -> None:
        assert {s.value for s in ToolRunStatus} == {
            "pending",
            "queued",
            "running",
            "completed",
            "failed",
            "cancelled",
            "approval_pending",
        }


# ---------------------------------------------------------------------------
# Report schemas
# ---------------------------------------------------------------------------


class TestReportGenerateInput:
    def test_defaults(self) -> None:
        payload = ReportGenerateInput(scan_id="scan-1234")
        assert payload.tier is ReportTier.MIDGARD
        assert payload.format is ReportFormat.JSON

    @pytest.mark.parametrize(
        "fmt",
        [
            ReportFormat.HTML,
            ReportFormat.PDF,
            ReportFormat.JSON,
            ReportFormat.SARIF,
            ReportFormat.JUNIT,
            ReportFormat.CSV,
        ],
    )
    def test_all_formats_valid(self, fmt: ReportFormat) -> None:
        payload = ReportGenerateInput(scan_id="scan-1234", format=fmt)
        assert payload.format is fmt


# ---------------------------------------------------------------------------
# Policy / scope schemas
# ---------------------------------------------------------------------------


class TestPolicyEvaluateInput:
    def test_default_passive(self) -> None:
        payload = PolicyEvaluateInput(tool_id="nuclei", target="example.com")
        assert payload.risk_level is PolicyRiskLevel.PASSIVE
        assert payload.estimated_cost_cents == 0

    def test_high_cost_rejected(self) -> None:
        with pytest.raises(ValidationError):
            PolicyEvaluateInput(
                tool_id="nuclei", target="example.com", estimated_cost_cents=20_000
            )


class TestScopeVerifyInput:
    @pytest.mark.parametrize("port", [1, 80, 443, 65_535])
    def test_valid_ports(self, port: int) -> None:
        payload = ScopeVerifyInput(target="example.com", port=port)
        assert payload.port == port

    @pytest.mark.parametrize("port", [0, -1, 65_536])
    def test_invalid_ports_rejected(self, port: int) -> None:
        with pytest.raises(ValidationError):
            ScopeVerifyInput(target="example.com", port=port)


class TestPolicyEvaluationOutcome:
    def test_closed_taxonomy(self) -> None:
        assert {o.value for o in PolicyEvaluationOutcome} == {
            "allowed",
            "denied",
            "requires_approval",
        }
