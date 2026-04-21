"""Unit tests for MCP ``policy.*`` and ``scope.*`` tools (Backlog/dev1_md §13).

The policy tool is a pure-function wrapper around :class:`PolicyEngine`
(no DB, no network). We inject custom factories so each test runs against
a deterministic policy + scope rule set.

The tests bypass FastMCP's ``ToolError`` wrapping by invoking the
registered tool's underlying coroutine directly so the closed-taxonomy
:class:`MCPError` instances propagate as-is.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from uuid import UUID

import pytest
from mcp.server.fastmcp import FastMCP

from src.mcp.audit_logger import MCPAuditLogger
from src.mcp.auth import MCPAuthContext
from src.mcp.context import set_audit_logger, set_auth_override
from src.mcp.exceptions import TenantMismatchError
from src.mcp.schemas.policy import (
    PolicyEvaluateInput,
    PolicyEvaluateResult,
    PolicyEvaluationOutcome,
    PolicyRiskLevel,
    ScopeVerifyInput,
    ScopeVerifyResult,
)
from src.mcp.services.policy_service import (
    set_policy_engine_factory,
    set_scope_engine_factory,
)
from src.mcp.tools import policy as policy_tools
from src.policy.policy_engine import PlanTier, PolicyEngine, TenantPolicy
from src.policy.scope import ScopeEngine, ScopeKind, ScopeRule


@pytest.fixture()
def app(auth_ctx: MCPAuthContext, audit_logger: MCPAuditLogger) -> FastMCP:
    set_auth_override(auth_ctx)
    set_audit_logger(audit_logger)
    instance = FastMCP(name="argus-policy-test")
    policy_tools.register(instance)
    return instance


@pytest.fixture(autouse=True)
def _reset_factories() -> Iterator[None]:
    """Ensure other tests don't leak a custom factory into ours."""
    set_scope_engine_factory(None)
    set_policy_engine_factory(None)
    try:
        yield
    finally:
        set_scope_engine_factory(None)
        set_policy_engine_factory(None)


def _tool_fn(app: FastMCP, name: str):
    return app._tool_manager._tools[name].fn  # type: ignore[attr-defined]


def _call(app: FastMCP, name: str, payload: object) -> object:
    return asyncio.run(_tool_fn(app, name)(payload=payload))


def _allow_example_scope() -> ScopeEngine:
    return ScopeEngine(
        rules=(
            ScopeRule(
                kind=ScopeKind.DOMAIN,
                pattern="example.com",
                deny=False,
            ),
        )
    )


def _enterprise_policy(tenant_id: str) -> tuple[PolicyEngine, TenantPolicy]:
    policy = TenantPolicy(
        tenant_id=UUID(tenant_id),
        plan_tier=PlanTier.ENTERPRISE,
    )
    return PolicyEngine(policy), policy


def _free_policy(tenant_id: str) -> tuple[PolicyEngine, TenantPolicy]:
    policy = TenantPolicy(
        tenant_id=UUID(tenant_id),
        plan_tier=PlanTier.FREE,
    )
    return PolicyEngine(policy), policy


class TestScopeVerify:
    def test_allowed_target_returns_allowed_true(self, app: FastMCP) -> None:
        set_scope_engine_factory(lambda _t: _allow_example_scope())
        result = _call(
            app,
            "scope.verify",
            ScopeVerifyInput(target="https://example.com"),
        )
        assert isinstance(result, ScopeVerifyResult)
        assert result.allowed is True
        assert result.target == "https://example.com"

    def test_unrelated_target_returns_allowed_false(self, app: FastMCP) -> None:
        set_scope_engine_factory(lambda _t: _allow_example_scope())
        result = _call(
            app,
            "scope.verify",
            ScopeVerifyInput(target="https://malicious.example.org"),
        )
        assert isinstance(result, ScopeVerifyResult)
        assert result.allowed is False
        assert result.failure_summary

    def test_cross_tenant_id_in_payload_rejected(
        self, app: FastMCP, other_tenant_id: str
    ) -> None:
        with pytest.raises(TenantMismatchError):
            _call(
                app,
                "scope.verify",
                ScopeVerifyInput(
                    target="https://example.com",
                    tenant_id=other_tenant_id,
                ),
            )

    def test_invalid_target_rejected(self) -> None:
        # Empty target is rejected at schema time by Pydantic.
        with pytest.raises(Exception):
            ScopeVerifyInput(target="")


class TestPolicyEvaluate:
    def test_passive_recon_allowed_with_owned_target(self, app: FastMCP) -> None:
        set_scope_engine_factory(lambda _t: _allow_example_scope())
        set_policy_engine_factory(_enterprise_policy)
        result = _call(
            app,
            "policy.evaluate",
            PolicyEvaluateInput(
                tool_id="subfinder",
                target="https://example.com",
                risk_level=PolicyRiskLevel.PASSIVE,
            ),
        )
        assert isinstance(result, PolicyEvaluateResult)
        assert result.outcome is PolicyEvaluationOutcome.ALLOWED
        assert result.requires_approval is False
        assert result.risk_level is PolicyRiskLevel.PASSIVE

    def test_high_risk_requires_approval_for_owned_target(self, app: FastMCP) -> None:
        set_scope_engine_factory(lambda _t: _allow_example_scope())
        set_policy_engine_factory(_enterprise_policy)
        result = _call(
            app,
            "policy.evaluate",
            PolicyEvaluateInput(
                tool_id="nuclei",
                target="https://example.com",
                risk_level=PolicyRiskLevel.HIGH,
            ),
        )
        assert isinstance(result, PolicyEvaluateResult)
        # Enterprise allows HIGH but it requires approval per policy.
        assert result.outcome in {
            PolicyEvaluationOutcome.REQUIRES_APPROVAL,
            PolicyEvaluationOutcome.DENIED,
        }
        assert result.risk_level is PolicyRiskLevel.HIGH

    def test_destructive_blocked_for_free_plan(self, app: FastMCP) -> None:
        set_scope_engine_factory(lambda _t: _allow_example_scope())
        set_policy_engine_factory(_free_policy)
        result = _call(
            app,
            "policy.evaluate",
            PolicyEvaluateInput(
                tool_id="demo_rce",
                target="https://example.com",
                risk_level=PolicyRiskLevel.DESTRUCTIVE,
            ),
        )
        assert isinstance(result, PolicyEvaluateResult)
        assert result.outcome is PolicyEvaluationOutcome.DENIED
        assert result.failure_summary

    def test_target_not_in_scope_denied(self, app: FastMCP) -> None:
        set_scope_engine_factory(lambda _t: _allow_example_scope())
        set_policy_engine_factory(_enterprise_policy)
        result = _call(
            app,
            "policy.evaluate",
            PolicyEvaluateInput(
                tool_id="nuclei",
                target="https://malicious.example.org",
                risk_level=PolicyRiskLevel.LOW,
            ),
        )
        assert isinstance(result, PolicyEvaluateResult)
        assert result.outcome is PolicyEvaluationOutcome.DENIED
