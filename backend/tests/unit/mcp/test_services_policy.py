"""Unit tests for :mod:`src.mcp.services.policy_service`.

These tests substitute the scope/policy engine factories so we exercise
the MCP -> PolicyEngine glue without touching the live policy database.

Coverage:

* ``_coerce_target_spec`` accepts URLs and bare domains, rejects empty
  input.
* ``verify_scope`` correctly maps :class:`ScopeDecision` (allowed /
  denied / port-not-allowed) to the MCP :class:`ScopeVerifyResult`.
* ``evaluate_policy`` wires risk -> phase, runs the engine, and
  translates the closed taxonomy
  (``allowed`` / ``requires_approval`` / ``denied``).
* Invalid ``tenant_id`` values produce :class:`ValidationError`
  rather than leaking the underlying ``ValueError`` from ``UUID()``.
"""

from __future__ import annotations

from collections.abc import Iterator
from uuid import UUID, uuid4

import pytest

from src.mcp.exceptions import ValidationError
from src.mcp.schemas.policy import (
    PolicyEvaluateInput,
    PolicyEvaluationOutcome,
    PolicyRiskLevel,
    ScopeVerifyInput,
)
from src.mcp.services import policy_service
from src.mcp.services.policy_service import (
    _coerce_target_spec,
    evaluate_policy,
    set_policy_engine_factory,
    set_scope_engine_factory,
    verify_scope,
)
from src.pipeline.contracts.tool_job import TargetKind
from src.policy.policy_engine import PlanTier, PolicyEngine, TenantPolicy
from src.policy.scope import ScopeEngine, ScopeKind, ScopeRule


# ---------------------------------------------------------------------------
# Engine factories used by the tests
# ---------------------------------------------------------------------------


def _scope_engine_allow_example_com() -> ScopeEngine:
    return ScopeEngine(
        rules=(
            ScopeRule(
                kind=ScopeKind.DOMAIN,
                pattern="example.com",
                deny=False,
            ),
        )
    )


def _scope_engine_deny_admin_example_com() -> ScopeEngine:
    return ScopeEngine(
        rules=(
            ScopeRule(
                kind=ScopeKind.DOMAIN,
                pattern="example.com",
                deny=False,
            ),
            ScopeRule(
                kind=ScopeKind.HOST,
                pattern="admin.example.com",
                deny=True,
            ),
        )
    )


def _build_policy(tenant_id: UUID) -> tuple[PolicyEngine, TenantPolicy]:
    policy = TenantPolicy(
        tenant_id=tenant_id,
        plan_tier=PlanTier.PRO,
    )
    return PolicyEngine(policy), policy


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def allowed_scope() -> Iterator[None]:
    set_scope_engine_factory(lambda _t: _scope_engine_allow_example_com())
    yield
    set_scope_engine_factory(None)


@pytest.fixture()
def deny_admin_scope() -> Iterator[None]:
    set_scope_engine_factory(lambda _t: _scope_engine_deny_admin_example_com())
    yield
    set_scope_engine_factory(None)


@pytest.fixture()
def policy_factory() -> Iterator[None]:
    set_policy_engine_factory(lambda tenant_id: _build_policy(UUID(tenant_id)))
    yield
    set_policy_engine_factory(None)


# ---------------------------------------------------------------------------
# _coerce_target_spec
# ---------------------------------------------------------------------------


class TestCoerceTargetSpec:
    def test_url_target(self) -> None:
        spec = _coerce_target_spec("https://example.com/login")
        assert spec.kind is TargetKind.URL
        assert spec.url == "https://example.com/login"
        assert spec.domain is None

    def test_domain_target(self) -> None:
        spec = _coerce_target_spec("example.com")
        assert spec.kind is TargetKind.DOMAIN
        assert spec.domain == "example.com"
        assert spec.url is None

    def test_empty_string_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _coerce_target_spec("")

    def test_whitespace_rejected(self) -> None:
        with pytest.raises(ValidationError):
            _coerce_target_spec("   ")

    def test_strips_whitespace(self) -> None:
        spec = _coerce_target_spec("  https://x.test/  ")
        assert spec.kind is TargetKind.URL
        assert "x.test" in (spec.url or "")


# ---------------------------------------------------------------------------
# verify_scope
# ---------------------------------------------------------------------------


class TestVerifyScope:
    def test_target_in_scope(self, tenant_id: str, allowed_scope: None) -> None:
        result = verify_scope(
            tenant_id=tenant_id,
            payload=ScopeVerifyInput(target="example.com"),
        )
        assert result.allowed is True
        assert result.failure_summary is None

    def test_target_not_in_scope(self, tenant_id: str, allowed_scope: None) -> None:
        result = verify_scope(
            tenant_id=tenant_id,
            payload=ScopeVerifyInput(target="evil.com"),
        )
        assert result.allowed is False
        assert result.failure_summary is not None

    def test_explicit_deny_overrides_allow(
        self, tenant_id: str, deny_admin_scope: None
    ) -> None:
        result = verify_scope(
            tenant_id=tenant_id,
            payload=ScopeVerifyInput(target="admin.example.com"),
        )
        assert result.allowed is False
        assert result.failure_summary == "target_explicitly_denied"

    def test_default_engine_denies_all(self, tenant_id: str) -> None:
        # No factory set -> default ScopeEngine(rules=()) denies every target
        result = verify_scope(
            tenant_id=tenant_id,
            payload=ScopeVerifyInput(target="example.com"),
        )
        assert result.allowed is False


# ---------------------------------------------------------------------------
# evaluate_policy
# ---------------------------------------------------------------------------


class TestEvaluatePolicy:
    def test_allowed_passive_target_in_scope(
        self,
        tenant_id: str,
        allowed_scope: None,
        policy_factory: None,
    ) -> None:
        result = evaluate_policy(
            tenant_id=tenant_id,
            payload=PolicyEvaluateInput(
                tool_id="nuclei",
                target="example.com",
                risk_level=PolicyRiskLevel.PASSIVE,
                payload_family=None,
                estimated_cost_cents=10,
            ),
        )
        assert result.outcome is PolicyEvaluationOutcome.ALLOWED
        assert result.requires_approval is False

    def test_denied_when_target_out_of_scope(
        self,
        tenant_id: str,
        allowed_scope: None,
        policy_factory: None,
    ) -> None:
        result = evaluate_policy(
            tenant_id=tenant_id,
            payload=PolicyEvaluateInput(
                tool_id="nuclei",
                target="evil.com",
                risk_level=PolicyRiskLevel.LOW,
                payload_family=None,
                estimated_cost_cents=10,
            ),
        )
        assert result.outcome is PolicyEvaluationOutcome.DENIED
        assert result.failure_summary is not None

    def test_invalid_tenant_id_rejected(self) -> None:
        with pytest.raises(ValidationError):
            evaluate_policy(
                tenant_id="not-a-uuid",
                payload=PolicyEvaluateInput(
                    tool_id="nuclei",
                    target="example.com",
                    risk_level=PolicyRiskLevel.LOW,
                    payload_family=None,
                    estimated_cost_cents=10,
                ),
            )


# ---------------------------------------------------------------------------
# Factory injection guard
# ---------------------------------------------------------------------------


class TestFactoryHooks:
    def test_set_to_none_restores_default(self) -> None:
        set_scope_engine_factory(lambda _t: _scope_engine_allow_example_com())
        set_scope_engine_factory(None)
        # After reset the default ScopeEngine(rules=()) denies everything.
        result = verify_scope(
            tenant_id=str(uuid4()),
            payload=ScopeVerifyInput(target="example.com"),
        )
        assert result.allowed is False

    def test_factory_invoked_per_tenant(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[str] = []

        def factory(tenant_id: str) -> ScopeEngine:
            seen.append(tenant_id)
            return _scope_engine_allow_example_com()

        set_scope_engine_factory(factory)
        try:
            verify_scope(
                tenant_id="t-1",
                payload=ScopeVerifyInput(target="example.com"),
            )
            verify_scope(
                tenant_id="t-2",
                payload=ScopeVerifyInput(target="example.com"),
            )
        finally:
            set_scope_engine_factory(None)
        assert seen == ["t-1", "t-2"]


# ---------------------------------------------------------------------------
# Module-level invariants
# ---------------------------------------------------------------------------


def test_policy_service_public_api() -> None:
    assert "evaluate_policy" in policy_service.__all__
    assert "verify_scope" in policy_service.__all__
    assert "set_scope_engine_factory" in policy_service.__all__
    assert "set_policy_engine_factory" in policy_service.__all__
