"""Shared fixtures for the P5 executable-playbook integration suite.

These tests drive the *real*, signed playbook catalog under
``backend/config/playbooks`` end-to-end through the P4 pipeline
(planner -> executor -> oracle -> evidence -> cleanup) against a deterministic
in-process stub transport. No production network, DB, or Docker is touched:

* SI-2 — the stub only answers requests to the in-scope ``target.internal``
  host; it never reaches a real third party.
* SI-3 — secrets (session cookies, passwords, OTPs, tokens) are injected on the
  execution layer and redacted before they ever land in evidence.
* SI-1 — approval-gated playbooks are exercised on both paths: denied without a
  valid Engagement Authorization Profile (``WAITING_APPROVAL``, not executed)
  and executed once an EAP pre-authorizes the class + target.
"""

from __future__ import annotations

import types
from collections.abc import Callable, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from src.auth.session_store import SessionStore
from src.orchestration.auth_config import PrincipalRole
from src.pipeline.contracts.tool_job import TargetKind, TargetSpec
from src.playbooks.actions import HttpRequestSpec, HttpResponse
from src.playbooks.executor import EapApprovalGate, ScenarioExecutor, ScenarioResult
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.planner import (
    EndpointContext,
    PlannedScenario,
    ScenarioPlanner,
    ScenarioPlanningContext,
)
from src.playbooks.registry import PlaybookRegistry
from src.playbooks.schema import HttpMethod, InputKind, Playbook
from src.policy.audit import AuditLogger, InMemoryAuditSink
from src.policy.engagement_authorization import (
    ActionClass,
    EngagementAuthorizationProfile,
    EngagementAuthorizationService,
)
from src.sandbox.signing import KeyManager, public_key_id

# In-scope, non-routable stub host used by every scenario (SI-2).
TARGET_HOST = "target.internal"

Responder = Callable[[HttpRequestSpec, "str | None"], HttpResponse]

_CATALOG_DIR = Path(__file__).resolve().parents[3] / "config" / "playbooks"


# ---------------------------------------------------------------------------
# Deterministic stub transport (records requests, replays scripted responses)
# ---------------------------------------------------------------------------


class StubTransport:
    """Record-and-respond :class:`ScenarioTransport` — no real network."""

    def __init__(self, responder: Responder) -> None:
        self._responder = responder
        self.calls: list[HttpRequestSpec] = []
        self.principals: list[str | None] = []

    def send(self, spec: HttpRequestSpec, *, principal: str | None = None) -> HttpResponse:
        self.calls.append(spec)
        self.principals.append(principal)
        return self._responder(spec, principal)

    def cookie_for(self, principal: str) -> set[str]:
        """Return the distinct ``Cookie`` header values seen for a principal."""
        return {
            spec.headers.get("Cookie", "")
            for spec, who in zip(self.calls, self.principals)
            if who == principal
        }


# ---------------------------------------------------------------------------
# Registry / playbook access (real signed catalog)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def playbook_registry() -> PlaybookRegistry:
    registry = PlaybookRegistry(_CATALOG_DIR)
    registry.load()
    return registry


@pytest.fixture()
def get_playbook(playbook_registry: PlaybookRegistry) -> Callable[[str], Playbook]:
    return playbook_registry.get


# ---------------------------------------------------------------------------
# Target + sessions
# ---------------------------------------------------------------------------


@pytest.fixture()
def target() -> TargetSpec:
    return TargetSpec(kind=TargetKind.URL, url=f"https://{TARGET_HOST}/api/v1/resource")


def build_session_store(principals: Mapping[str, bool]) -> SessionStore:
    """Create an isolated session per principal.

    ``principals`` maps a principal id to whether it should carry an
    authenticated cookie (``True``) or remain credential-less (``False``,
    e.g. an anonymous principal). Each authenticated principal gets its own
    distinct secret so cross-principal contamination is detectable.
    """
    store = SessionStore(allow_env=False)
    for principal, authenticated in principals.items():
        session = store.create_session(principal, PrincipalRole.OWNER)
        if authenticated:
            session.set_cookie(f"sess_{principal}", f"{principal}-secret-token", domain=TARGET_HOST)
            session.set_bearer(f"{principal}-bearer-not-real")
    return store


def run_executor(
    playbook: Playbook,
    transport: StubTransport,
    principals: Mapping[str, bool],
    target: TargetSpec,
    *,
    gate: EapApprovalGate | None = None,
) -> ScenarioResult:
    """Execute ``playbook`` against ``transport`` with isolated principal sessions."""
    executor = ScenarioExecutor(
        transport=transport,
        session_store=build_session_store(principals),
        approval_gate=gate,
        sleep=lambda _s: None,
    )
    return executor.execute(playbook, target=target)


# ---------------------------------------------------------------------------
# Planner helper
# ---------------------------------------------------------------------------


def plan_scenario(
    playbook: Playbook,
    *,
    method: HttpMethod,
    path: str,
    input_kinds: frozenset[InputKind],
    principals: frozenset[str],
    is_preauthorized: Callable[[Playbook], bool] | None = None,
) -> PlannedScenario:
    """Plan a single playbook against one discovered endpoint."""
    planner = ScenarioPlanner([playbook])
    ctx = ScenarioPlanningContext(
        endpoints=[
            EndpointContext(method=method, path=path, has_openapi=False, input_kinds=input_kinds)
        ],
        available_principals=principals,
        available_capabilities=frozenset({"http_client"}),
        is_preauthorized=is_preauthorized,
    )
    scenarios = planner.plan(ctx)
    assert len(scenarios) == 1
    return scenarios[0]


# ---------------------------------------------------------------------------
# EAP approval gate factory (SI-1)
# ---------------------------------------------------------------------------


@pytest.fixture()
def eap_gate_factory(
    tmp_path: Path,
) -> Callable[..., EapApprovalGate]:
    """Return a builder for a real, EAP-backed approval gate.

    The builder signs an :class:`EngagementAuthorizationProfile` with a fresh
    Ed25519 key whose public half is loaded into a :class:`KeyManager`, so the
    gate performs genuine signature verification + scope enforcement.
    """
    private_key = Ed25519PrivateKey.generate()
    keys_dir = tmp_path / "eap_keys"
    keys_dir.mkdir()
    kid = _write_public_key(private_key, keys_dir)
    key_manager = KeyManager(keys_dir)
    key_manager.load()
    assert kid in key_manager.loaded_key_ids
    eap_service = EngagementAuthorizationService(
        key_manager=key_manager, audit_logger=AuditLogger(InMemoryAuditSink())
    )

    def _build(
        allow_classes: frozenset[ActionClass],
        *,
        action_class: ActionClass | None = None,
        targets: tuple[str, ...] = (TARGET_HOST,),
    ) -> EapApprovalGate:
        profile = EngagementAuthorizationService.sign_profile(
            EngagementAuthorizationProfile(
                engagement_id="eng-p5-scen-005",
                authorized_by="ciso@example.test",
                targets=targets,
                allow_action_classes=allow_classes,
                max_request_budget=10_000,
                expires=datetime.now(tz=timezone.utc) + timedelta(days=1),
            ),
            private_key=private_key,
        )
        resolver = (lambda _pb: action_class) if action_class is not None else None
        return EapApprovalGate(
            eap_service=eap_service,
            profile=profile,
            tenant_id=uuid4(),
            action_class_resolver=resolver,
        )

    return _build


def _write_public_key(private_key: Ed25519PrivateKey, keys_dir: Path) -> str:
    public_key = private_key.public_key()
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    kid = public_key_id(public_key)
    (keys_dir / f"{kid}.ed25519.pub").write_bytes(raw)
    return kid


# ---------------------------------------------------------------------------
# Shared assertions
# ---------------------------------------------------------------------------


def assert_confirmed(result: ScenarioResult) -> None:
    """Assert a scenario reached CONFIRMED, built evidence, and cleaned up."""
    assert result.executed is True
    assert result.is_confirmed is True
    assert result.state.status in {
        ScenarioStatus.CLEANUP_COMPLETE,
        ScenarioStatus.CLEANUP_FAILED,
    }
    assert result.state.status is ScenarioStatus.CLEANUP_COMPLETE
    assert result.evidence is not None
    assert len(result.evidence.sha256()) == 64
    assert any(r.is_finding for r in result.oracle_results)


def assert_rejected(result: ScenarioResult) -> None:
    """Assert a scenario executed but the oracle found no vulnerability."""
    assert result.executed is True
    assert result.is_confirmed is False
    assert ScenarioStatus.REJECTED in {s.status for s in result.history}
    assert result.state.status is ScenarioStatus.CLEANUP_COMPLETE
    assert not any(r.is_finding for r in result.oracle_results)


def assert_cleanup_complete(result: ScenarioResult) -> None:
    assert result.cleanup is not None
    assert result.cleanup.status is ScenarioStatus.CLEANUP_COMPLETE


def assert_secret_absent(result: ScenarioResult, *plaintext_secrets: str) -> None:
    """Assert no plaintext secret survives into the persisted evidence.

    Session secrets (cookies / bearer tokens) are applied only on the execution
    layer and never recorded in the exchange, so they can never reach evidence
    (SI-3). This proves that invariant without requiring a ``[REDACTED]`` marker.
    """
    assert result.evidence is not None
    blob = result.evidence.canonical_json()
    for secret in plaintext_secrets:
        assert secret not in blob, f"secret leaked into evidence: {secret!r}"


def assert_secret_redacted(result: ScenarioResult, *plaintext_secrets: str) -> None:
    """Assert secrets present in a recorded body/response are redacted (SI-3)."""
    assert result.evidence is not None
    blob = result.evidence.canonical_json()
    assert "[REDACTED]" in blob, "expected at least one redaction marker in evidence"
    for secret in plaintext_secrets:
        assert secret not in blob, f"secret leaked into evidence: {secret!r}"


# ---------------------------------------------------------------------------
# Fixtures exposing the helpers (avoids cross-conftest import ambiguity)
# ---------------------------------------------------------------------------


@pytest.fixture()
def transport_factory() -> type[StubTransport]:
    return StubTransport


@pytest.fixture()
def run_scenario(
    target: TargetSpec,
) -> Callable[..., ScenarioResult]:
    def _run(
        playbook: Playbook,
        transport: StubTransport,
        principals: Mapping[str, bool],
        *,
        gate: EapApprovalGate | None = None,
    ) -> ScenarioResult:
        return run_executor(playbook, transport, principals, target, gate=gate)

    return _run


@pytest.fixture()
def plan_pb() -> Callable[..., PlannedScenario]:
    return plan_scenario


@pytest.fixture()
def checks() -> types.SimpleNamespace:
    return types.SimpleNamespace(
        confirmed=assert_confirmed,
        rejected=assert_rejected,
        cleanup=assert_cleanup_complete,
        redacted=assert_secret_redacted,
        absent=assert_secret_absent,
    )
