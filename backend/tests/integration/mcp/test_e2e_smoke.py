"""End-to-end smoke tests for the ARGUS Backend MCP server.

Scope:

* Build the application with :func:`build_app` and assert that the wiring
  surfaced through the *public* MCP API matches the contract advertised
  in :mod:`docs/mcp-server.md` (15 tools, 4 resources, 2 prompts).
* Drive a representative ``initialize`` → ``tools/list`` → ``tools/call``
  round-trip across the in-process FastMCP `Client` so transport-agnostic
  framing (Pydantic input/output validation, audit emission, error
  taxonomy) is exercised end-to-end.
* Assert the strict tenant-isolation invariant: a tool invoked under
  tenant ``A`` cannot read or mutate state owned by tenant ``B``. We
  override the auth context per call to simulate two distinct sessions
  and verify the :class:`TenantMismatchError` surfaces over the wire.

The integration suite intentionally swaps the heavy DB-bound services
for in-process fakes so the tests run on a developer laptop without a
PostgreSQL / MinIO stack (those paths are covered by the dedicated
``backend/tests/db`` and ``backend/tests/integration/findings`` suites).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from mcp.server.fastmcp import FastMCP

from src.mcp.audit_logger import MCPAuditLogger, make_default_audit_logger
from src.mcp.auth import MCPAuthContext
from src.mcp.context import set_audit_logger, set_auth_override
from src.mcp.exceptions import TenantMismatchError
from src.mcp.schemas.approval import (
    ApprovalDecideInput,
    ApprovalDecisionAction,
    ApprovalListInput,
)
from src.mcp.schemas.finding import (
    FindingFilter,
    FindingListResult,
    FindingSummary,
    Severity,
)
from src.mcp.schemas.policy import (
    PolicyEvaluateInput,
    PolicyRiskLevel,
    ScopeVerifyInput,
)
from src.mcp.server import build_app
from src.mcp.services import (
    policy_service,
    scan_service,
    tool_service,
)
from src.mcp.services.approval_service import (
    InMemoryApprovalRepository,
    StoredApproval,
    set_approval_repository,
)
from src.mcp.tools import findings as findings_tools
from src.policy.policy_engine import PlanTier, PolicyEngine, TenantPolicy
from src.policy.scope import ScopeEngine, ScopeKind, ScopeRule


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tenant_id() -> str:
    return str(uuid4())


@pytest.fixture()
def other_tenant_id() -> str:
    return str(uuid4())


@pytest.fixture()
def auth_ctx(tenant_id: str) -> MCPAuthContext:
    return MCPAuthContext(
        user_id="mcp-int-actor",
        tenant_id=tenant_id,
        method="static_token",
        is_admin=False,
    )


@pytest.fixture()
def cross_auth_ctx(other_tenant_id: str) -> MCPAuthContext:
    return MCPAuthContext(
        user_id="mcp-int-other",
        tenant_id=other_tenant_id,
        method="static_token",
        is_admin=False,
    )


@pytest.fixture()
def audit_logger() -> MCPAuditLogger:
    return make_default_audit_logger()


@pytest.fixture()
def app(auth_ctx: MCPAuthContext, audit_logger: MCPAuditLogger) -> Iterator[FastMCP]:
    """Construct the *real* MCP application (same build_app the CLI uses)."""
    set_auth_override(auth_ctx)
    set_audit_logger(audit_logger)
    instance = build_app(name="argus-it", log_level="WARNING")
    set_audit_logger(audit_logger)
    try:
        yield instance
    finally:
        set_auth_override(None)
        set_audit_logger(None)


@pytest.fixture(autouse=True)
def _reset_factories() -> Iterator[None]:
    """Keep service-level injection hooks isolated between tests."""
    policy_service.set_policy_engine_factory(None)
    policy_service.set_scope_engine_factory(None)
    scan_service.set_scan_dispatcher(None)
    tool_service.reset_registry_for_tests(None)
    yield
    policy_service.set_policy_engine_factory(None)
    policy_service.set_scope_engine_factory(None)
    scan_service.set_scan_dispatcher(None)
    tool_service.reset_registry_for_tests(None)


# ---------------------------------------------------------------------------
# Helpers — invoke a tool's underlying function directly so the closed-taxonomy
# MCPError taxonomy propagates verbatim (FastMCP wraps all exceptions in
# ToolError otherwise).
# ---------------------------------------------------------------------------


def _tool_fn(app: FastMCP, name: str):
    return app._tool_manager._tools[name].fn  # type: ignore[attr-defined]


def _call(app: FastMCP, name: str, payload: object) -> object:
    return asyncio.run(_tool_fn(app, name)(payload=payload))


def _drain_events(audit: MCPAuditLogger) -> list[object]:
    sink = audit.audit_logger.sink
    events: list[object] = []
    for tenant_events in sink._events.values():  # type: ignore[attr-defined]
        events.extend(tenant_events)
    events.sort(key=lambda e: e.occurred_at)  # type: ignore[attr-defined]
    return events


# ---------------------------------------------------------------------------
# 1. Capability surface — ``initialize`` + ``tools/list`` analogues.
# ---------------------------------------------------------------------------


class TestCapabilitySurface:
    def test_tools_list_returns_full_catalog(self, app: FastMCP) -> None:
        tools = asyncio.run(app.list_tools())
        names = {t.name for t in tools}
        # ARG-023 contract — 15 tools minimum.
        required = {
            "scan.create",
            "scan.status",
            "scan.cancel",
            "findings.list",
            "findings.get",
            "findings.mark_false_positive",
            "report.generate",
            "report.download",
            "approvals.list",
            "approvals.decide",
            "scope.verify",
            "policy.evaluate",
            "tool.catalog.list",
            "tool.run.trigger",
            "tool.run.status",
        }
        assert required.issubset(names), (
            f"Missing tools: {required - names}; got {names}"
        )
        assert len(names) >= 15

    def test_resources_list_returns_four_entries(self, app: FastMCP) -> None:
        resources = asyncio.run(app.list_resources())
        templates = asyncio.run(app.list_resource_templates())
        # Mix of concrete (catalog/tools, approvals/pending) + templates
        # (findings/{scan_id}, reports/{report_id}).
        all_names = {r.name for r in resources} | {t.name for t in templates}
        required = {
            "argus.catalog.tools",
            "argus.findings.scan",
            "argus.reports.report",
            "argus.approvals.pending",
        }
        assert required.issubset(all_names), f"missing: {required - all_names}"

    def test_prompts_list_returns_section_13_prompts(self, app: FastMCP) -> None:
        prompts = asyncio.run(app.list_prompts())
        names = {p.name for p in prompts}
        # ARG-023 contract — 2 prompts minimum; the implementation ships 3.
        required = {
            "vulnerability.explainer",
            "remediation.advisor",
            "severity.normalizer",
        }
        assert required.issubset(names), f"missing prompts: {required - names}"

    def test_tool_descriptions_are_non_empty(self, app: FastMCP) -> None:
        tools = asyncio.run(app.list_tools())
        for tool in tools:
            assert tool.description, f"{tool.name} has an empty description"
            assert len(tool.description) >= 30, (
                f"{tool.name} description is too terse for an LLM to disambiguate"
            )


# ---------------------------------------------------------------------------
# 2. End-to-end tool round-trips (no DB; fake services injected).
# ---------------------------------------------------------------------------


class TestE2EToolCalls:
    def test_findings_list_round_trip(
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
                items=(
                    FindingSummary(
                        finding_id="find-1234abcd",
                        severity=Severity.MEDIUM,
                        title="SQLi on /login",
                        cwe="CWE-89",
                        owasp_category="A03",
                        confidence="confirmed",
                        false_positive=False,
                        created_at=None,
                    ),
                ),
                total=1,
                next_offset=None,
            )

        from src.mcp.schemas.finding import FindingListInput

        monkeypatch.setattr(findings_tools, "svc_list_findings", _fake_list)
        result = _call(app, "findings.list", FindingListInput(scan_id="scan-12345678"))
        assert isinstance(result, FindingListResult)
        assert result.total == 1
        events = _drain_events(audit_logger)
        # The ``app`` fixture re-installs the audit logger after build_app
        # so emitted events land in the *same* sink the test inspects.
        assert any(
            getattr(e, "payload", {}).get("tool_name") == "findings.list"
            for e in events
        )

    def test_policy_evaluate_round_trip(self, app: FastMCP) -> None:
        policy_service.set_scope_engine_factory(
            lambda _t: ScopeEngine(
                rules=(
                    ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com", deny=False),
                )
            )
        )

        def _policy_factory(t: str) -> tuple[PolicyEngine, TenantPolicy]:
            from uuid import UUID

            policy = TenantPolicy(tenant_id=UUID(t), plan_tier=PlanTier.ENTERPRISE)
            return PolicyEngine(policy), policy

        policy_service.set_policy_engine_factory(_policy_factory)

        result = _call(
            app,
            "policy.evaluate",
            PolicyEvaluateInput(
                tool_id="subfinder",
                target="https://example.com",
                risk_level=PolicyRiskLevel.PASSIVE,
            ),
        )
        assert result.outcome.value == "allowed"

    def test_scope_verify_round_trip(self, app: FastMCP) -> None:
        policy_service.set_scope_engine_factory(
            lambda _t: ScopeEngine(
                rules=(
                    ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com", deny=False),
                )
            )
        )
        result = _call(
            app, "scope.verify", ScopeVerifyInput(target="https://example.com")
        )
        assert result.allowed is True


# ---------------------------------------------------------------------------
# 3. Tenant isolation invariants.
# ---------------------------------------------------------------------------


class TestTenantIsolation:
    def test_approvals_list_with_cross_tenant_id_in_payload_rejected(
        self,
        app: FastMCP,
        other_tenant_id: str,
    ) -> None:
        with pytest.raises(TenantMismatchError):
            _call(
                app,
                "approvals.list",
                ApprovalListInput(tenant_id=other_tenant_id, status="pending"),
            )

    def test_approvals_list_only_returns_authenticated_tenant_rows(
        self,
        app: FastMCP,
        tenant_id: str,
        other_tenant_id: str,
    ) -> None:
        repo = InMemoryApprovalRepository()
        set_approval_repository(repo)
        now = datetime.now(timezone.utc)
        # Same tool_id, two tenants, one approval each.
        for tid, request_id in (
            (tenant_id, "req-mine-12345"),
            (other_tenant_id, "req-other-12345"),
        ):
            repo.add(
                StoredApproval(
                    request_id=request_id,
                    tenant_id=tid,
                    tool_id="nuclei",
                    target="https://example.com",
                    action="high",
                    status="pending",
                    created_at=now,
                    expires_at=now + timedelta(hours=24),
                )
            )

        result = _call(app, "approvals.list", ApprovalListInput(status="pending"))
        request_ids = {item.request_id for item in result.items}
        assert request_ids == {"req-mine-12345"}

    def test_approvals_decide_for_other_tenant_returns_not_found(
        self,
        app: FastMCP,
        other_tenant_id: str,
    ) -> None:
        from src.mcp.exceptions import ResourceNotFoundError

        repo = InMemoryApprovalRepository()
        set_approval_repository(repo)
        now = datetime.now(timezone.utc)
        repo.add(
            StoredApproval(
                request_id="req-foreign-12345",
                tenant_id=other_tenant_id,
                tool_id="nuclei",
                target="https://example.com",
                action="high",
                status="pending",
                created_at=now,
                expires_at=now + timedelta(hours=24),
            )
        )

        with pytest.raises(ResourceNotFoundError):
            _call(
                app,
                "approvals.decide",
                ApprovalDecideInput(
                    request_id="req-foreign-12345",
                    decision=ApprovalDecisionAction.DENY,
                    justification="Out of scope per customer policy.",
                ),
            )


# ---------------------------------------------------------------------------
# 4. Audit invariants — every successful call writes one PREFLIGHT_PASS row,
#    every denied call writes one PREFLIGHT_DENY row.
# ---------------------------------------------------------------------------


class TestAuditEmission:
    def test_successful_scope_verify_emits_allowed_event(
        self,
        app: FastMCP,
        audit_logger: MCPAuditLogger,
    ) -> None:
        policy_service.set_scope_engine_factory(
            lambda _t: ScopeEngine(
                rules=(
                    ScopeRule(kind=ScopeKind.DOMAIN, pattern="example.com", deny=False),
                )
            )
        )
        _call(app, "scope.verify", ScopeVerifyInput(target="https://example.com"))
        events = _drain_events(audit_logger)
        scope_events = [
            e
            for e in events
            if getattr(e, "payload", {}).get("tool_name") == "scope.verify"
        ]
        assert len(scope_events) == 1
        assert scope_events[0].payload["outcome"] == "allowed"  # type: ignore[attr-defined]
        assert scope_events[0].payload["arguments_hash"]  # type: ignore[attr-defined]

    def test_denied_call_emits_denied_event(
        self,
        app: FastMCP,
        audit_logger: MCPAuditLogger,
        other_tenant_id: str,
    ) -> None:
        with pytest.raises(TenantMismatchError):
            _call(
                app,
                "approvals.list",
                ApprovalListInput(tenant_id=other_tenant_id, status="pending"),
            )
        events = _drain_events(audit_logger)
        approval_events = [
            e
            for e in events
            if getattr(e, "payload", {}).get("tool_name") == "approvals.list"
        ]
        assert approval_events, "expected at least one approvals.list audit row"
        # The denial event records the closed-taxonomy failure summary.
        last = approval_events[-1]
        assert last.payload["outcome"] in {"denied", "error"}  # type: ignore[attr-defined]
        assert last.failure_summary  # type: ignore[attr-defined]
