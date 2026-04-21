"""Unit tests for MCP resources (Backlog/dev1_md §13).

Asserts that:

* Tenant-scoped resources resolve via the authenticated tenant id.
* Resource templates validate the URI variable (length / shape).
* Pending-approvals and tools-catalog resources marshal data through the
  service layer with strict JSON shape (sorted keys, compact separators).

We invoke the underlying registered coroutine directly rather than going
through ``FastMCP.read_resource``, because the high-level entry point
expects a real session context (``Context.request_context``) that is only
available inside a JSON-RPC session.  Each resource module imports its
service helpers into its local namespace, so monkey-patching targets the
resource module, not the service module.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone

import pytest
from mcp.server.fastmcp import FastMCP

from src.mcp.audit_logger import MCPAuditLogger
from src.mcp.auth import MCPAuthContext
from src.mcp.context import set_audit_logger, set_auth_override
from src.mcp.exceptions import ValidationError
from src.mcp.resources import approvals as approvals_resource
from src.mcp.resources import findings as findings_resource
from src.mcp.resources import reports as reports_resource
from src.mcp.resources import tools_catalog as tools_catalog_resource
from src.mcp.schemas.finding import (
    FindingFilter,
    FindingListResult,
    FindingSummary,
    Severity,
)
from src.mcp.schemas.report import (
    ReportDownloadResult,
    ReportFormat,
)
from src.mcp.schemas.tool_run import (
    ToolCatalogEntry,
    ToolCatalogListResult,
    ToolRiskLevel,
)
from src.mcp.services.approval_service import (
    InMemoryApprovalRepository,
    StoredApproval,
    set_approval_repository,
)


def _make_finding_summary() -> FindingSummary:
    return FindingSummary(
        finding_id="find-1234abcd",
        severity=Severity.MEDIUM,
        title="SQL injection on /login",
        cwe="CWE-89",
        owasp_category="A03",
        confidence="confirmed",
        false_positive=False,
        created_at=None,
    )


def _make_catalog_entry(tool_id: str = "subfinder") -> ToolCatalogEntry:
    return ToolCatalogEntry(
        tool_id=tool_id,
        category="recon",
        phase="recon",
        risk_level=ToolRiskLevel.PASSIVE,
        requires_approval=False,
        description="Find subdomains.",
    )


@pytest.fixture()
def app(auth_ctx: MCPAuthContext, audit_logger: MCPAuditLogger) -> FastMCP:
    set_auth_override(auth_ctx)
    set_audit_logger(audit_logger)
    instance = FastMCP(name="argus-resources-test")
    findings_resource.register(instance)
    reports_resource.register(instance)
    approvals_resource.register(instance)
    tools_catalog_resource.register(instance)
    return instance


def _template_fn(app: FastMCP, uri_template: str):
    """Return the registered template's underlying coroutine."""
    return app._resource_manager._templates[uri_template].fn  # type: ignore[attr-defined]


def _resource_fn(app: FastMCP, uri: str):
    """Return the registered fixed-URI resource's underlying coroutine.

    Some resources without URI vars are still stored as templates (because
    the function takes a ``ctx`` kwarg that FastMCP cannot bind to the
    URI), so we fall back to the templates dict if the resource is not in
    the concrete-URI dict.
    """
    rm = app._resource_manager  # type: ignore[attr-defined]
    if uri in rm._resources:
        return rm._resources[uri].fn
    if uri in rm._templates:
        return rm._templates[uri].fn
    raise KeyError(f"resource {uri!r} not registered")


def _call_template(app: FastMCP, uri_template: str, **kwargs: object) -> str:
    return asyncio.run(_template_fn(app, uri_template)(**kwargs))


def _call_resource(app: FastMCP, uri: str) -> str:
    return asyncio.run(_resource_fn(app, uri)())


class TestFindingsResource:
    def test_returns_capped_findings_for_tenant(
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
            captured["tenant_id"] = tenant_id
            captured["scan_id"] = scan_id
            captured["limit"] = limit
            return FindingListResult(
                items=(_make_finding_summary(),), total=1, next_offset=None
            )

        monkeypatch.setattr(findings_resource, "list_findings", _fake_list)
        body = _call_template(
            app, "argus://findings/{scan_id}", scan_id="scan-12345678"
        )
        decoded = json.loads(body)
        assert decoded["scan_id"] == "scan-12345678"
        assert decoded["total"] == 1
        assert decoded["items"][0]["finding_id"] == "find-1234abcd"
        assert captured["limit"] == 200

    def test_short_scan_id_rejected(self, app: FastMCP) -> None:
        with pytest.raises(ValidationError):
            _call_template(app, "argus://findings/{scan_id}", scan_id="abc")

    def test_oversized_scan_id_rejected(self, app: FastMCP) -> None:
        with pytest.raises(ValidationError):
            _call_template(app, "argus://findings/{scan_id}", scan_id="x" * 65)


class TestReportsResource:
    def test_returns_metadata_envelope(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
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

        monkeypatch.setattr(reports_resource, "get_report_download", _fake_download)
        body = _call_template(
            app, "argus://reports/{report_id}", report_id="report-12345678"
        )
        decoded = json.loads(body)
        assert decoded["report_id"] == "report-12345678"
        assert decoded["presigned_url"] == "https://example.com/dl/abc"
        assert decoded["sha256"] == "0" * 64

    def test_short_report_id_rejected(self, app: FastMCP) -> None:
        with pytest.raises(ValidationError):
            _call_template(app, "argus://reports/{report_id}", report_id="abc")


class TestApprovalsPendingResource:
    @pytest.fixture()
    def repo(self) -> Iterator[InMemoryApprovalRepository]:
        instance = InMemoryApprovalRepository()
        set_approval_repository(instance)
        try:
            yield instance
        finally:
            set_approval_repository(InMemoryApprovalRepository())

    def test_returns_only_pending_for_authenticated_tenant(
        self,
        app: FastMCP,
        repo: InMemoryApprovalRepository,
        tenant_id: str,
        other_tenant_id: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        repo.add(
            StoredApproval(
                request_id="req-pending-1",
                tenant_id=tenant_id,
                tool_id="nuclei",
                target="https://example.com",
                action="high",
                status="pending",
                created_at=now,
                expires_at=now + timedelta(hours=24),
            )
        )
        repo.add(
            StoredApproval(
                request_id="req-pending-other",
                tenant_id=other_tenant_id,
                tool_id="nuclei",
                target="https://attacker.example.org",
                action="high",
                status="pending",
                created_at=now,
                expires_at=now + timedelta(hours=24),
            )
        )
        body = _call_resource(app, "argus://approvals/pending")
        decoded = json.loads(body)
        assert decoded["total"] == 1
        assert decoded["items"][0]["request_id"] == "req-pending-1"

    def test_excludes_completed_approvals(
        self,
        app: FastMCP,
        repo: InMemoryApprovalRepository,
        tenant_id: str,
    ) -> None:
        now = datetime.now(timezone.utc)
        repo.add(
            StoredApproval(
                request_id="req-granted-1",
                tenant_id=tenant_id,
                tool_id="nuclei",
                target="https://example.com",
                action="high",
                status="granted",
                created_at=now,
                expires_at=now + timedelta(hours=24),
            )
        )
        body = _call_resource(app, "argus://approvals/pending")
        decoded = json.loads(body)
        assert decoded["total"] == 0


class TestToolsCatalogResource:
    def test_returns_catalog_snapshot(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def _fake_list_catalog(
            *,
            category: str | None = None,
            risk_level=None,
            requires_approval=None,
            limit: int = 50,
            offset: int = 0,
        ) -> ToolCatalogListResult:
            return ToolCatalogListResult(items=(_make_catalog_entry(),), total=1)

        monkeypatch.setattr(tools_catalog_resource, "list_catalog", _fake_list_catalog)
        body = _call_resource(app, "argus://catalog/tools")
        decoded = json.loads(body)
        assert decoded["total"] == 1
        assert decoded["items"][0]["tool_id"] == "subfinder"

    def test_payload_uses_compact_json(
        self,
        app: FastMCP,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        def _fake_list_catalog(
            *,
            category: str | None = None,
            risk_level=None,
            requires_approval=None,
            limit: int = 50,
            offset: int = 0,
        ) -> ToolCatalogListResult:
            return ToolCatalogListResult(items=(), total=0)

        monkeypatch.setattr(tools_catalog_resource, "list_catalog", _fake_list_catalog)
        body = _call_resource(app, "argus://catalog/tools")
        # Compact JSON: no whitespace after `:` or `,`.
        assert ", " not in body
        assert ": " not in body
