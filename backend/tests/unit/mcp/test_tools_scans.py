"""Unit tests for MCP ``scan.*`` tools (Backlog/dev1_md §13).

The tools are thin wrappers around :mod:`src.mcp.services.scan_service`. The
tests below mock the service layer (so no DB is required) and assert:

* ``scan.create`` enforces justification rules for the DEEP profile.
* ``scan.create`` propagates input to the service and returns a typed result
  with the audit-event id attached.
* ``scan.status`` and ``scan.cancel`` defer to the service unchanged and
  emit per-call audit events.
* Errors from the service are surfaced via the closed ``MCPError`` taxonomy
  (never a raw exception).
* Cross-tenant attempts triggered via service errors stay tenant-scoped.
"""

from __future__ import annotations

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP

from src.mcp.audit_logger import MCPAuditLogger
from src.mcp.auth import MCPAuthContext
from src.mcp.context import set_audit_logger, set_auth_override
from src.mcp.exceptions import (
    ApprovalRequiredError,
    ResourceNotFoundError,
    UpstreamServiceError,
    ValidationError,
)
from src.mcp.schemas.common import ToolResultStatus
from src.mcp.schemas.scan import (
    ScanCancelInput,
    ScanCreateInput,
    ScanCreateResult,
    ScanProfile,
    ScanStatus,
    ScanStatusInput,
    ScanStatusResult,
)
from src.mcp.tools import scans as scans_tools


def _drain_events(audit_logger: MCPAuditLogger) -> list[object]:
    sink = audit_logger.audit_logger.sink
    events: list[object] = []
    for tenant_events in sink._events.values():  # type: ignore[attr-defined]
        events.extend(tenant_events)
    events.sort(key=lambda e: e.occurred_at)  # type: ignore[attr-defined]
    return events


@pytest.fixture()
def app(auth_ctx: MCPAuthContext, audit_logger: MCPAuditLogger) -> FastMCP:
    """A FastMCP app with only the scan.* tools and an overridden auth ctx."""
    set_auth_override(auth_ctx)
    set_audit_logger(audit_logger)
    instance = FastMCP(name="argus-scans-test")
    scans_tools.register(instance)
    return instance


def _tool_fn(app: FastMCP, name: str):
    """Return the un-wrapped tool callable.

    Calling :meth:`FastMCP.call_tool` would re-raise any internal
    ``MCPError`` wrapped inside ``mcp.server.fastmcp.exceptions.ToolError``,
    erasing the exception type / code we want to assert on. Tests instead
    invoke the registered Python function directly so the closed-taxonomy
    :class:`MCPError` instance propagates as-is.
    """
    return app._tool_manager._tools[name].fn  # type: ignore[attr-defined]


def _call(app: FastMCP, name: str, payload: object) -> object:
    """Invoke the registered tool callable with a typed payload (no ctx)."""
    fn = _tool_fn(app, name)
    return asyncio.run(fn(payload=payload))


class TestScanCreateValidation:
    """Argument-level guards (DEEP profile, justification length, etc.)."""

    def test_deep_profile_without_justification_rejected(self, app: FastMCP) -> None:
        payload = ScanCreateInput(
            target="https://example.com",
            profile=ScanProfile.DEEP,
        )
        with pytest.raises(ApprovalRequiredError) as exc_info:
            _call(app, "scan.create", payload)
        assert exc_info.value.code == "mcp_approval_required"

    def test_short_justification_rejected(self, app: FastMCP) -> None:
        payload = ScanCreateInput(
            target="https://example.com",
            profile=ScanProfile.STANDARD,
            justification="short",
        )
        with pytest.raises(ValidationError) as exc_info:
            _call(app, "scan.create", payload)
        assert exc_info.value.code == "mcp_validation_error"

    def test_invalid_target_rejected_by_pydantic(self) -> None:
        # Pydantic validates the input *before* the tool fn runs; we can
        # therefore assert directly on the schema constructor.
        with pytest.raises(Exception):
            ScanCreateInput(target="  ", profile=ScanProfile.STANDARD)


class TestScanCreateHappyPath:
    """Service-level integration via monkeypatching."""

    def test_quick_scan_returns_typed_result(
        self,
        app: FastMCP,
        tenant_id: str,
        audit_logger: MCPAuditLogger,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: dict[str, object] = {}

        async def _fake_enqueue(
            *, tenant_id: str, user_id: str, payload: ScanCreateInput
        ) -> ScanCreateResult:
            captured["tenant_id"] = tenant_id
            captured["user_id"] = user_id
            captured["target"] = payload.target
            return ScanCreateResult(
                scan_id="scan-12345678",
                status=ScanStatus.PENDING,
                target=payload.target,
                profile=payload.profile,
                requires_approval=False,
            )

        monkeypatch.setattr(scans_tools, "svc_enqueue_scan", _fake_enqueue)
        result = _call(
            app,
            "scan.create",
            ScanCreateInput(target="https://example.com", profile=ScanProfile.QUICK),
        )

        assert isinstance(result, ScanCreateResult)
        assert result.scan_id == "scan-12345678"
        assert result.status is ScanStatus.PENDING
        assert result.requires_approval is False
        assert result.audit_event_id is not None

        assert captured["tenant_id"] == tenant_id
        # Audit row recorded the allowed call.
        events = _drain_events(audit_logger)
        assert len(events) == 1
        assert events[0].payload["tool_name"] == "scan.create"  # type: ignore[attr-defined]
        assert events[0].payload["outcome"] == "allowed"  # type: ignore[attr-defined]

    def test_deep_scan_with_long_justification_passes(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _fake_enqueue(
            *, tenant_id: str, user_id: str, payload: ScanCreateInput
        ) -> ScanCreateResult:
            return ScanCreateResult(
                scan_id="scan-deep1234",
                status=ScanStatus.PENDING,
                target=payload.target,
                profile=payload.profile,
                requires_approval=False,
            )

        monkeypatch.setattr(scans_tools, "svc_enqueue_scan", _fake_enqueue)
        result = _call(
            app,
            "scan.create",
            ScanCreateInput(
                target="https://example.com",
                profile=ScanProfile.DEEP,
                justification="Tier-1 incident response triage by ops team.",
            ),
        )
        assert isinstance(result, ScanCreateResult)
        assert result.scan_id == "scan-deep1234"

    def test_service_failure_mapped_to_upstream_error(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
        audit_logger: MCPAuditLogger,
    ) -> None:
        async def _boom(*_, **__):
            raise RuntimeError("internal: secret SQL")

        monkeypatch.setattr(scans_tools, "svc_enqueue_scan", _boom)
        with pytest.raises(UpstreamServiceError) as exc_info:
            _call(
                app,
                "scan.create",
                ScanCreateInput(target="https://example.com"),
            )
        # The leaked SQL never reaches the LLM client.
        assert "secret SQL" not in exc_info.value.message
        events = _drain_events(audit_logger)
        assert events[-1].failure_summary == "mcp_internal_error"  # type: ignore[attr-defined]


class TestScanStatus:
    def test_status_returns_typed_result(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _fake_status(*, tenant_id: str, scan_id: str) -> ScanStatusResult:
            return ScanStatusResult(
                scan_id=scan_id,
                status=ScanStatus.RUNNING,
                progress_percent=42,
                target="https://example.com",
                started_at=None,
                finished_at=None,
                finding_counts={"high": 1},
            )

        monkeypatch.setattr(scans_tools, "svc_get_scan_status", _fake_status)
        result = _call(app, "scan.status", ScanStatusInput(scan_id="scan-12345678"))
        assert isinstance(result, ScanStatusResult)
        assert result.progress_percent == 42
        assert result.status is ScanStatus.RUNNING

    def test_status_not_found_propagates_as_resource_not_found(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
        audit_logger: MCPAuditLogger,
    ) -> None:
        async def _missing(*, tenant_id: str, scan_id: str) -> ScanStatusResult:
            raise ResourceNotFoundError("not found")

        monkeypatch.setattr(scans_tools, "svc_get_scan_status", _missing)
        with pytest.raises(ResourceNotFoundError) as exc_info:
            _call(app, "scan.status", ScanStatusInput(scan_id="scan-12345678"))
        assert exc_info.value.code == "mcp_resource_not_found"
        events = _drain_events(audit_logger)
        assert events[-1].failure_summary == "mcp_resource_not_found"  # type: ignore[attr-defined]
        # Extra payload (scan_id) still recorded.
        assert events[-1].payload["scan_id"] == "scan-12345678"  # type: ignore[attr-defined]


class TestScanCancel:
    def test_cancel_records_new_state_and_audit(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
        audit_logger: MCPAuditLogger,
    ) -> None:
        async def _fake_cancel(
            *, tenant_id: str, scan_id: str, reason: str
        ) -> ScanStatus:
            assert reason == "operator-stop"
            return ScanStatus.CANCELLED

        monkeypatch.setattr(scans_tools, "svc_cancel_scan", _fake_cancel)
        result = _call(
            app,
            "scan.cancel",
            ScanCancelInput(scan_id="scan-cancel0", reason="operator-stop"),
        )
        assert result.status is ToolResultStatus.SUCCESS
        assert result.new_state is ScanStatus.CANCELLED
        events = _drain_events(audit_logger)
        assert events[-1].payload["scan_id"] == "scan-cancel0"  # type: ignore[attr-defined]

    def test_cancel_short_reason_rejected_by_pydantic(self) -> None:
        # Pydantic enforces the min_length=4 reason at schema construction.
        with pytest.raises(Exception):
            ScanCancelInput(scan_id="scan-12345678", reason="no")


class TestScanCreateInputValidation:
    """Pure schema validation — no app required."""

    def test_target_must_match_pattern(self) -> None:
        with pytest.raises(Exception):
            ScanCreateInput(target="not a url with spaces")  # type: ignore[arg-type]

    def test_justification_max_length(self) -> None:
        with pytest.raises(Exception):
            ScanCreateInput(target="example.com", justification="x" * 600)  # type: ignore[arg-type]


class TestScanStatusInputValidation:
    def test_short_id_rejected(self) -> None:
        with pytest.raises(Exception):
            ScanStatusInput(scan_id="abc")  # type: ignore[arg-type]


class TestScanCancelInputValidation:
    def test_short_id_rejected(self) -> None:
        with pytest.raises(Exception):
            ScanCancelInput(scan_id="abc", reason="long enough reason")  # type: ignore[arg-type]
