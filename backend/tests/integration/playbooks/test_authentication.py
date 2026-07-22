"""P5 integration tests: authentication playbooks end-to-end on a stub target.

Covers ``auth.direct-protected-route`` (missing authentication) and
``mfa.direct-step-skip`` (MFA step-up bypass). Each proves the full
planner -> executor -> oracle -> evidence -> cleanup path: CONFIRMED against a
modelled vulnerability, REJECTED when the target is secure, evidence redacted.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from src.playbooks.actions import HttpRequestSpec, HttpResponse
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.schema import HttpMethod, InputKind, Playbook

_ACCOUNT = {"id": 42, "email": "user@example.test", "balance": 1000, "plan": "pro"}
_VAULT = {"id": 7, "email": "mfa@example.test", "recovery_codes": ["a", "b"]}


# ---------------------------------------------------------------------------
# auth.direct-protected-route
# ---------------------------------------------------------------------------


def _auth_vuln(_spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
    # Broken: the protected route serves data even to the anonymous principal.
    return HttpResponse(status=200, body=json.dumps(_ACCOUNT))


def _auth_secure(_spec: HttpRequestSpec, principal: str | None) -> HttpResponse:
    if principal == "anon":
        return HttpResponse(status=401, body='{"error":"unauthenticated"}')
    return HttpResponse(status=200, body=json.dumps(_ACCOUNT))


def test_auth_direct_route_is_planned(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    scenario = plan_pb(
        get_playbook("auth.direct-protected-route"),
        method=HttpMethod.GET,
        path="/api/v1/account",
        input_kinds=frozenset({InputKind.HEADER}),
        principals=frozenset({"user", "anon"}),
    )
    assert scenario.status is ScenarioStatus.PLANNED


def test_auth_direct_route_confirmed(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("auth.direct-protected-route")
    transport = transport_factory(_auth_vuln)
    result = run_scenario(pb, transport, {"user": True, "anon": False})
    checks.confirmed(result)
    checks.cleanup(result)
    # The authenticated baseline used the user's cookie on the wire ...
    assert transport.cookie_for("user") == {"sess_user=user-secret-token"}
    # ... but the anonymous probe carried no credential ...
    assert transport.cookie_for("anon") == {""}
    # ... and no secret ever reached the persisted evidence (SI-3).
    checks.absent(result, "user-secret-token", "user-bearer-not-real")


def test_auth_direct_route_rejected_when_enforced(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("auth.direct-protected-route")
    result = run_scenario(pb, transport_factory(_auth_secure), {"user": True, "anon": False})
    checks.rejected(result)


# ---------------------------------------------------------------------------
# mfa.direct-step-skip
# ---------------------------------------------------------------------------


def _mfa_vuln(_spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
    # Broken: an MFA-pending session reaches the MFA-protected vault.
    return HttpResponse(status=200, body=json.dumps(_VAULT))


def _mfa_secure(_spec: HttpRequestSpec, principal: str | None) -> HttpResponse:
    if principal == "mfa_pending":
        return HttpResponse(status=403, body='{"error":"mfa_required"}')
    return HttpResponse(status=200, body=json.dumps(_VAULT))


def test_mfa_step_skip_is_planned(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    scenario = plan_pb(
        get_playbook("mfa.direct-step-skip"),
        method=HttpMethod.GET,
        path="/api/v1/vault",
        input_kinds=frozenset({InputKind.HEADER}),
        principals=frozenset({"mfa_complete", "mfa_pending"}),
    )
    assert scenario.status is ScenarioStatus.PLANNED


def test_mfa_step_skip_confirmed(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("mfa.direct-step-skip")
    result = run_scenario(
        pb, transport_factory(_mfa_vuln), {"mfa_complete": True, "mfa_pending": True}
    )
    checks.confirmed(result)
    checks.cleanup(result)
    checks.absent(result, "mfa_complete-secret-token", "mfa_pending-secret-token")


def test_mfa_step_skip_rejected_when_enforced(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("mfa.direct-step-skip")
    result = run_scenario(
        pb, transport_factory(_mfa_secure), {"mfa_complete": True, "mfa_pending": True}
    )
    checks.rejected(result)
