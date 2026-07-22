"""Tests for the P4 :class:`ScenarioExecutor` (lifecycle, oracles, evidence,
approval gate, session isolation, and always-run cleanup)."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.auth.session_store import SessionStore
from src.orchestration.auth_config import PrincipalRole
from src.pipeline.contracts.tool_job import TargetKind, TargetSpec
from src.playbooks.actions import HttpRequestSpec, HttpResponse
from src.playbooks.executor import (
    ApprovalGateDecision,
    EapApprovalGate,
    ScenarioExecutor,
    ScenarioStatus,
)
from src.playbooks.lifecycle import ScenarioStatus as LifecycleStatus
from src.playbooks.schema import Playbook
from src.policy.audit import AuditLogger, InMemoryAuditSink
from src.policy.engagement_authorization import (
    ActionClass,
    EngagementAuthorizationProfile,
    EngagementAuthorizationService,
)
from src.sandbox.signing import KeyManager


# ---------------------------------------------------------------------------
# Stub network transport
# ---------------------------------------------------------------------------


@dataclass
class _Call:
    principal: str | None
    method: str
    url: str
    cookie: str | None
    headers: dict[str, str]


class StubTransport:
    """Deterministic, record-and-respond transport (no real network)."""

    def __init__(self, responder: Callable[[HttpRequestSpec, str | None], HttpResponse]) -> None:
        self._responder = responder
        self.calls: list[_Call] = []

    def send(self, spec: HttpRequestSpec, *, principal: str | None = None) -> HttpResponse:
        self.calls.append(
            _Call(
                principal=principal,
                method=spec.method.value,
                url=spec.url,
                cookie=spec.headers.get("Cookie"),
                headers=dict(spec.headers),
            )
        )
        return self._responder(spec, principal)


# ---------------------------------------------------------------------------
# Playbook builders (concrete URLs — no template variables)
# ---------------------------------------------------------------------------


def _base_playbook(**over: object) -> dict[str, object]:
    data: dict[str, object] = {
        "schema_version": 1,
        "playbook_id": "idor.exec-confirm",
        "version": 1,
        "title": "IDOR exec test",
        "description": "Executor test playbook; not a production entry.",
        "category": "authorization",
        "applies_when": {"methods": ["GET"]},
        "required_principals": ["owner", "attacker"],
        "required_capabilities": [],
        "risk_level": "low",
        "requires_approval": False,
        "steps": [
            {
                "id": "owner_baseline",
                "action": "http_request",
                "principal": "owner",
                "save_as": "owner_resp",
                "params": {
                    "method": "GET",
                    "url": "https://api.example.com/api/v1/users/7",
                    "headers": {},
                },
            },
            {
                "id": "attacker_probe",
                "action": "http_request",
                "principal": "attacker",
                "save_as": "attacker_resp",
                "params": {
                    "method": "GET",
                    "url": "https://api.example.com/api/v1/users/7",
                    "headers": {},
                },
            },
        ],
        "assertions": [{"type": "authz", "params": {"sensitive_fields": ["email"]}}],
    }
    data.update(over)
    return data


def _playbook_with_cleanup() -> Playbook:
    data = _base_playbook(playbook_id="idor.exec-cleanup")
    steps = list(data["steps"])  # type: ignore[arg-type]
    steps.append(
        {
            "id": "register_del",
            "action": "register_cleanup",
            "params": {"cleanup_step_id": "del_test_acct"},
        }
    )
    data["steps"] = steps
    data["cleanup"] = [
        {
            "id": "del_test_acct",
            "action": "http_request",
            "params": {
                "method": "DELETE",
                "url": "https://api.example.com/api/v1/users/999",
                "headers": {},
            },
        }
    ]
    return Playbook(**data)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def session_store() -> SessionStore:
    store = SessionStore(allow_env=False)
    owner = store.create_session("owner", PrincipalRole.OWNER)
    owner.set_cookie("sess", "owner-secret", domain="api.example.com")
    attacker = store.create_session("attacker", PrincipalRole.ATTACKER)
    attacker.set_cookie("sess", "attacker-secret", domain="api.example.com")
    return store


@pytest.fixture()
def target() -> TargetSpec:
    return TargetSpec(kind=TargetKind.URL, url="https://api.example.com/api/v1/users/7")


_VICTIM = {"id": 7, "email": "victim@example.com"}


def _idor_responder(spec: HttpRequestSpec, principal: str | None) -> HttpResponse:
    # Simulated IDOR: both principals receive the victim's record.
    return HttpResponse(status=200, body=json.dumps(_VICTIM))


def _secure_responder(spec: HttpRequestSpec, principal: str | None) -> HttpResponse:
    if principal == "attacker":
        return HttpResponse(status=403, body="forbidden")
    return HttpResponse(status=200, body=json.dumps(_VICTIM))


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------


def test_confirmed_happy_path_with_evidence(
    session_store: SessionStore, target: TargetSpec
) -> None:
    transport = StubTransport(_idor_responder)
    executor = ScenarioExecutor(
        transport=transport, session_store=session_store, sleep=lambda _s: None
    )
    result = executor.execute(Playbook(**_base_playbook()), target=target)

    assert result.executed is True
    assert result.is_confirmed is True
    assert result.state.status is LifecycleStatus.CLEANUP_COMPLETE
    assert result.evidence is not None
    # Evidence is redaction-safe and carries a stable hash.
    assert len(result.evidence.sha256()) == 64
    assert any(r.is_finding for r in result.oracle_results)


# ---------------------------------------------------------------------------
# Session isolation (G-2)
# ---------------------------------------------------------------------------


def test_session_isolation_across_principals(
    session_store: SessionStore, target: TargetSpec
) -> None:
    transport = StubTransport(_idor_responder)
    executor = ScenarioExecutor(
        transport=transport, session_store=session_store, sleep=lambda _s: None
    )
    executor.execute(Playbook(**_base_playbook()), target=target)

    owner_calls = [c for c in transport.calls if c.principal == "owner"]
    attacker_calls = [c for c in transport.calls if c.principal == "attacker"]
    assert owner_calls and attacker_calls
    assert all(c.cookie == "sess=owner-secret" for c in owner_calls)
    assert all(c.cookie == "sess=attacker-secret" for c in attacker_calls)
    # No cross-contamination: owner never sees attacker's secret and vice versa.
    assert all("attacker-secret" not in (c.cookie or "") for c in owner_calls)
    assert all("owner-secret" not in (c.cookie or "") for c in attacker_calls)


# ---------------------------------------------------------------------------
# Cleanup always runs
# ---------------------------------------------------------------------------


def test_cleanup_runs_even_when_rejected(
    session_store: SessionStore, target: TargetSpec
) -> None:
    transport = StubTransport(_secure_responder)
    executor = ScenarioExecutor(
        transport=transport, session_store=session_store, sleep=lambda _s: None
    )
    result = executor.execute(_playbook_with_cleanup(), target=target)

    assert LifecycleStatus.REJECTED in {s.status for s in result.history}
    assert result.cleanup is not None
    assert result.cleanup.status is LifecycleStatus.CLEANUP_COMPLETE
    assert "del_test_acct" in result.cleanup.executed_step_ids
    # The cleanup DELETE actually went through the transport.
    assert any(c.method == "DELETE" for c in transport.calls)


# ---------------------------------------------------------------------------
# Approval gate (SI-1)
# ---------------------------------------------------------------------------


def test_approval_gated_without_gate_is_not_executed(
    session_store: SessionStore, target: TargetSpec
) -> None:
    transport = StubTransport(_idor_responder)
    executor = ScenarioExecutor(
        transport=transport, session_store=session_store, sleep=lambda _s: None
    )
    playbook = Playbook(
        **_base_playbook(
            playbook_id="idor.exec-gated", risk_level="high", requires_approval=True
        )
    )
    result = executor.execute(playbook, target=target)

    assert result.executed is False
    assert result.state.status is LifecycleStatus.WAITING_APPROVAL
    assert transport.calls == []  # nothing ran


def test_approval_gated_with_denying_gate_is_not_executed(
    session_store: SessionStore, target: TargetSpec
) -> None:
    class _DenyGate:
        def authorize(self, playbook: Playbook, tgt: TargetSpec) -> ApprovalGateDecision:
            return ApprovalGateDecision(authorized=False, reason="not pre-authorized")

    transport = StubTransport(_idor_responder)
    executor = ScenarioExecutor(
        transport=transport,
        session_store=session_store,
        approval_gate=_DenyGate(),
        sleep=lambda _s: None,
    )
    playbook = Playbook(
        **_base_playbook(
            playbook_id="idor.exec-gated2", risk_level="high", requires_approval=True
        )
    )
    result = executor.execute(playbook, target=target)
    assert result.executed is False
    assert result.state.status is LifecycleStatus.WAITING_APPROVAL
    assert transport.calls == []


def test_approval_gated_with_eap_preauthorization_executes(
    tmp_path,
    session_store: SessionStore,
    target: TargetSpec,
    ed25519_keypair: tuple[Ed25519PrivateKey, object, str],
) -> None:
    priv, pub, kid = ed25519_keypair
    keys = tmp_path / "_keys"
    keys.mkdir()
    (keys / f"{kid}.ed25519.pub").write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )
    key_manager = KeyManager(keys)
    key_manager.load()
    eap_service = EngagementAuthorizationService(
        key_manager=key_manager, audit_logger=AuditLogger(InMemoryAuditSink())
    )
    profile = EngagementAuthorizationService.sign_profile(
        EngagementAuthorizationProfile(
            engagement_id="eng-exec",
            authorized_by="ciso@example.com",
            targets=("example.com",),
            # authorization category → INJECTION_SAFE (default_action_class).
            allow_action_classes=frozenset({ActionClass.INJECTION_SAFE}),
            max_request_budget=1000,
            expires=datetime.now(tz=timezone.utc) + timedelta(days=1),
        ),
        private_key=priv,
    )
    gate = EapApprovalGate(
        eap_service=eap_service,
        profile=profile,
        tenant_id=uuid4(),
    )
    transport = StubTransport(_idor_responder)
    executor = ScenarioExecutor(
        transport=transport,
        session_store=session_store,
        approval_gate=gate,
        sleep=lambda _s: None,
    )
    playbook = Playbook(
        **_base_playbook(
            playbook_id="idor.exec-eap", risk_level="high", requires_approval=True
        )
    )
    result = executor.execute(playbook, target=target)

    assert result.executed is True
    assert result.approval_id is not None
    assert result.is_confirmed is True


def test_scenario_status_reexport_matches_lifecycle() -> None:
    # Executor re-exports ScenarioStatus for convenience; keep them identical.
    assert ScenarioStatus is LifecycleStatus
