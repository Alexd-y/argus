"""Unit tests for MCP ``report.*`` tools (Backlog/dev1_md §13).

Mocks the report service so the tests do not require a running PostgreSQL
or MinIO instance and asserts:

* ``report.generate`` enforces input shape and returns the queued report id.
* ``report.download`` echoes the presigned URL / SHA-256 from metadata
  without ever streaming raw bytes.
* Audit rows carry the ``report_id`` / ``format`` extras for observability.

The tests bypass FastMCP's ``ToolError`` wrapping by invoking the
registered tool's underlying coroutine directly.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import pytest
from mcp.server.fastmcp import FastMCP

from src.mcp.audit_logger import MCPAuditLogger
from src.mcp.auth import MCPAuthContext
from src.mcp.context import set_audit_logger, set_auth_override
from src.mcp.exceptions import ResourceNotFoundError
from src.mcp.schemas.report import (
    ReportDownloadInput,
    ReportDownloadResult,
    ReportFormat,
    ReportGenerateInput,
    ReportGenerateResult,
    ReportTier,
)
from src.mcp.tools import reports as reports_tools


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
    instance = FastMCP(name="argus-reports-test")
    reports_tools.register(instance)
    return instance


def _tool_fn(app: FastMCP, name: str):
    return app._tool_manager._tools[name].fn  # type: ignore[attr-defined]


def _call(app: FastMCP, name: str, payload: object) -> object:
    return asyncio.run(_tool_fn(app, name)(payload=payload))


class TestReportGenerate:
    def test_default_tier_and_format(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
        audit_logger: MCPAuditLogger,
    ) -> None:
        async def _fake_request(
            *,
            tenant_id: str,
            scan_id: str,
            tier: ReportTier,
            format: ReportFormat,
        ) -> ReportGenerateResult:
            assert tier is ReportTier.MIDGARD
            assert format is ReportFormat.JSON
            return ReportGenerateResult(
                report_id="report-12345678",
                scan_id=scan_id,
                tier=tier,
                format=format,
                queued=True,
            )

        monkeypatch.setattr(
            reports_tools, "svc_request_report_generation", _fake_request
        )
        result = _call(
            app,
            "report.generate",
            ReportGenerateInput(scan_id="scan-12345678"),
        )
        assert isinstance(result, ReportGenerateResult)
        assert result.report_id == "report-12345678"
        assert result.queued is True
        events = _drain_events(audit_logger)
        assert events[-1].payload["scan_id"] == "scan-12345678"  # type: ignore[attr-defined]
        assert events[-1].payload["tier"] == "midgard"  # type: ignore[attr-defined]
        assert events[-1].payload["format"] == "json"  # type: ignore[attr-defined]

    def test_explicit_tier_and_format_propagated(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        captured: dict[str, object] = {}

        async def _fake_request(
            *,
            tenant_id: str,
            scan_id: str,
            tier: ReportTier,
            format: ReportFormat,
        ) -> ReportGenerateResult:
            captured["tier"] = tier
            captured["format"] = format
            return ReportGenerateResult(
                report_id="report-12345678",
                scan_id=scan_id,
                tier=tier,
                format=format,
                queued=True,
            )

        monkeypatch.setattr(
            reports_tools, "svc_request_report_generation", _fake_request
        )
        _call(
            app,
            "report.generate",
            ReportGenerateInput(
                scan_id="scan-12345678",
                tier=ReportTier.VALHALLA,
                format=ReportFormat.SARIF,
            ),
        )
        assert captured["tier"] is ReportTier.VALHALLA
        assert captured["format"] is ReportFormat.SARIF

    def test_short_scan_id_rejected_by_schema(self) -> None:
        with pytest.raises(Exception):
            ReportGenerateInput(scan_id="abc")


class TestReportDownload:
    def test_returns_presigned_envelope(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
        audit_logger: MCPAuditLogger,
    ) -> None:
        expires = datetime.now(timezone.utc) + timedelta(hours=1)

        async def _fake_download(
            *, tenant_id: str, report_id: str, format: ReportFormat
        ) -> ReportDownloadResult:
            return ReportDownloadResult(
                report_id=report_id,
                format=format,
                presigned_url="https://example.com/dl/abc",
                sha256="0" * 64,
                expires_at=expires,
            )

        monkeypatch.setattr(reports_tools, "svc_get_report_download", _fake_download)
        result = _call(
            app,
            "report.download",
            ReportDownloadInput(report_id="report-12345678", format=ReportFormat.PDF),
        )
        assert isinstance(result, ReportDownloadResult)
        assert result.presigned_url == "https://example.com/dl/abc"
        assert result.sha256 == "0" * 64
        events = _drain_events(audit_logger)
        assert events[-1].payload["report_id"] == "report-12345678"  # type: ignore[attr-defined]
        assert events[-1].payload["format"] == "pdf"  # type: ignore[attr-defined]

    def test_pending_report_returns_empty_url(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _pending(
            *, tenant_id: str, report_id: str, format: ReportFormat
        ) -> ReportDownloadResult:
            return ReportDownloadResult(
                report_id=report_id,
                format=format,
                presigned_url=None,
                sha256=None,
                expires_at=None,
            )

        monkeypatch.setattr(reports_tools, "svc_get_report_download", _pending)
        result = _call(
            app,
            "report.download",
            ReportDownloadInput(report_id="report-12345678"),
        )
        assert isinstance(result, ReportDownloadResult)
        assert result.presigned_url is None
        assert result.sha256 is None

    def test_missing_report_returns_not_found(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        async def _missing(
            *, tenant_id: str, report_id: str, format: ReportFormat
        ) -> ReportDownloadResult:
            raise ResourceNotFoundError("not found")

        monkeypatch.setattr(reports_tools, "svc_get_report_download", _missing)
        with pytest.raises(ResourceNotFoundError):
            _call(
                app,
                "report.download",
                ReportDownloadInput(report_id="report-missing"),
            )
