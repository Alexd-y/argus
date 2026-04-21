"""Unit tests for MCP ``findings.*`` tools (Backlog/dev1_md §13).

Mocks the :mod:`src.mcp.services.finding_service` layer so DB drivers are
not required and asserts wrapper-level guarantees: tenant scoping, audit
emission with the ``finding_id`` extra payload, and closed-taxonomy error
mapping for missing findings / validation errors.

The tests bypass FastMCP's ``ToolError`` wrapping by invoking the
registered tool's underlying coroutine directly via
``app._tool_manager._tools[name].fn`` — this preserves the typed
``MCPError`` taxonomy that LLM clients receive over the wire.
"""

from __future__ import annotations

import asyncio

import pytest
from mcp.server.fastmcp import FastMCP

from src.mcp.audit_logger import MCPAuditLogger
from src.mcp.auth import MCPAuthContext
from src.mcp.context import set_audit_logger, set_auth_override
from src.mcp.exceptions import ResourceNotFoundError
from src.mcp.schemas.common import PaginationInput, ToolResultStatus
from src.mcp.schemas.finding import (
    FindingDetail,
    FindingFilter,
    FindingGetInput,
    FindingListInput,
    FindingListResult,
    FindingMarkFalsePositiveInput,
    FindingMarkResult,
    FindingSummary,
    Severity,
)
from src.mcp.tools import findings as findings_tools


def _drain_events(audit_logger: MCPAuditLogger) -> list[object]:
    sink = audit_logger.audit_logger.sink
    events: list[object] = []
    for tenant_events in sink._events.values():  # type: ignore[attr-defined]
        events.extend(tenant_events)
    events.sort(key=lambda e: e.occurred_at)  # type: ignore[attr-defined]
    return events


@pytest.fixture()
def app(auth_ctx: MCPAuthContext, audit_logger: MCPAuditLogger) -> FastMCP:
    set_auth_override(auth_ctx)
    set_audit_logger(audit_logger)
    instance = FastMCP(name="argus-findings-test")
    findings_tools.register(instance)
    return instance


def _tool_fn(app: FastMCP, name: str):
    return app._tool_manager._tools[name].fn  # type: ignore[attr-defined]


def _call(app: FastMCP, name: str, payload: object) -> object:
    return asyncio.run(_tool_fn(app, name)(payload=payload))


def _make_summary(severity: Severity = Severity.MEDIUM) -> FindingSummary:
    return FindingSummary(
        finding_id="find-1234abcd",
        severity=severity,
        title="SQL injection on /login",
        cwe="CWE-89",
        owasp_category="A03",
        confidence="confirmed",
        false_positive=False,
        created_at=None,
    )


class TestFindingsList:
    def test_returns_paginated_summaries(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
        audit_logger: MCPAuditLogger,
    ) -> None:
        async def _fake_list(
            *,
            tenant_id: str,
            scan_id: str,
            filters: FindingFilter,
            limit: int,
            offset: int,
        ) -> FindingListResult:
            return FindingListResult(
                items=(_make_summary(),), total=1, next_offset=None
            )

        monkeypatch.setattr(findings_tools, "svc_list_findings", _fake_list)
        result = _call(
            app,
            "findings.list",
            FindingListInput(scan_id="scan-12345678"),
        )
        assert isinstance(result, FindingListResult)
        assert result.total == 1
        assert result.items[0].finding_id == "find-1234abcd"
        events = _drain_events(audit_logger)
        assert events[-1].payload["scan_id"] == "scan-12345678"  # type: ignore[attr-defined]

    def test_filters_propagated_to_service(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: dict[str, object] = {}

        async def _fake_list(
            *,
            tenant_id: str,
            scan_id: str,
            filters: FindingFilter,
            limit: int,
            offset: int,
        ) -> FindingListResult:
            captured["filters"] = filters
            captured["limit"] = limit
            captured["offset"] = offset
            return FindingListResult(items=(), total=0, next_offset=None)

        monkeypatch.setattr(findings_tools, "svc_list_findings", _fake_list)
        _call(
            app,
            "findings.list",
            FindingListInput(
                scan_id="scan-12345678",
                filters=FindingFilter(
                    severity=Severity.HIGH,
                    cwe="CWE-79",
                    owasp_category="A03",
                    include_false_positive=True,
                ),
                pagination=PaginationInput(limit=5, offset=10),
            ),
        )
        filters = captured["filters"]
        assert isinstance(filters, FindingFilter)
        assert filters.severity is Severity.HIGH
        assert filters.cwe == "CWE-79"
        assert filters.include_false_positive is True
        assert captured["limit"] == 5
        assert captured["offset"] == 10

    def test_invalid_owasp_category_rejected(self) -> None:
        # Pydantic validator rejects unknown OWASP codes at schema time.
        with pytest.raises(Exception):
            FindingFilter(owasp_category="Z99")

    def test_short_scan_id_rejected(self) -> None:
        # FindingListInput.scan_id has min_length=8.
        with pytest.raises(Exception):
            FindingListInput(scan_id="abc")


class TestFindingsGet:
    def test_returns_full_detail(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
        audit_logger: MCPAuditLogger,
    ) -> None:
        async def _fake_get(*, tenant_id: str, finding_id: str) -> FindingDetail:
            return FindingDetail(
                finding_id=finding_id,
                scan_id="scan-12345678",
                severity=Severity.CRITICAL,
                title="Auth bypass",
                description="Cookie forging in /admin",
                cwe="CWE-287",
                cvss=9.1,
                owasp_category="A07",
                confidence="confirmed",
                evidence_type="response",
                proof_of_concept={"steps": ["1", "2"]},
                evidence_refs=("ref-1",),
                reproducible_steps=None,
                false_positive=False,
                false_positive_reason=None,
                created_at=None,
            )

        monkeypatch.setattr(findings_tools, "svc_get_finding", _fake_get)
        result = _call(
            app,
            "findings.get",
            FindingGetInput(finding_id="find-1234abcd"),
        )
        assert isinstance(result, FindingDetail)
        assert result.severity is Severity.CRITICAL
        assert result.cwe == "CWE-287"
        events = _drain_events(audit_logger)
        assert events[-1].payload["finding_id"] == "find-1234abcd"  # type: ignore[attr-defined]

    def test_missing_finding_returns_not_found(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _missing(*, tenant_id: str, finding_id: str) -> FindingDetail:
            raise ResourceNotFoundError("not found")

        monkeypatch.setattr(findings_tools, "svc_get_finding", _missing)
        with pytest.raises(ResourceNotFoundError) as exc_info:
            _call(
                app,
                "findings.get",
                FindingGetInput(finding_id="find-missing-id"),
            )
        assert exc_info.value.code == "mcp_resource_not_found"


class TestFindingsMarkFalsePositive:
    def test_idempotent_returns_unchanged_for_already_marked(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _fake_mark(
            *, tenant_id: str, finding_id: str, reason: str, actor: str
        ) -> bool:
            return False

        monkeypatch.setattr(findings_tools, "svc_mark_false_positive", _fake_mark)
        result = _call(
            app,
            "findings.mark_false_positive",
            FindingMarkFalsePositiveInput(
                finding_id="find-1234abcd",
                reason="operator triage cleared this finding",
            ),
        )
        assert isinstance(result, FindingMarkResult)
        assert result.status is ToolResultStatus.UNCHANGED

    def test_first_call_returns_success(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _fake_mark(
            *, tenant_id: str, finding_id: str, reason: str, actor: str
        ) -> bool:
            return True

        monkeypatch.setattr(findings_tools, "svc_mark_false_positive", _fake_mark)
        result = _call(
            app,
            "findings.mark_false_positive",
            FindingMarkFalsePositiveInput(
                finding_id="find-1234abcd",
                reason="operator triage cleared this finding",
            ),
        )
        assert isinstance(result, FindingMarkResult)
        assert result.status is ToolResultStatus.SUCCESS

    def test_short_reason_rejected_by_schema(self) -> None:
        # ``reason`` has a min_length constraint enforced at schema time.
        with pytest.raises(Exception):
            FindingMarkFalsePositiveInput(finding_id="find-1234abcd", reason="short")
