"""P5 integration test: session invalidation playbook on a stub target.

``session.logout-invalidation`` proves that a session token replayed after a
logout must be rejected. The stub is stateful: once the logout POST is seen, a
secure target rejects the replayed GET (401) while a broken target keeps
honouring the cookie (200) -> a genuine, stub-driven CONFIRMED/REJECTED flip.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from src.playbooks.actions import HttpRequestSpec, HttpResponse
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.schema import HttpMethod, InputKind, Playbook

_ME = {"id": 9, "email": "user@example.test", "role": "user"}


def _make_logout_vuln() -> Callable[[HttpRequestSpec, "str | None"], HttpResponse]:
    def _r(spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
        if spec.method.value == "POST":
            return HttpResponse(status=200, body=json.dumps({"status": "logged_out"}))
        # Broken: the session cookie still works after logout.
        return HttpResponse(status=200, body=json.dumps(_ME))

    return _r


def _make_logout_secure() -> Callable[[HttpRequestSpec, "str | None"], HttpResponse]:
    state = {"logged_out": False}

    def _r(spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
        if spec.method.value == "POST":
            state["logged_out"] = True
            return HttpResponse(status=200, body=json.dumps({"status": "logged_out"}))
        if state["logged_out"]:
            return HttpResponse(status=401, body=json.dumps({"error": "session_expired"}))
        return HttpResponse(status=200, body=json.dumps(_ME))

    return _r


def test_logout_invalidation_is_planned(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    scenario = plan_pb(
        get_playbook("session.logout-invalidation"),
        method=HttpMethod.GET,
        path="/api/v1/me",
        input_kinds=frozenset({InputKind.COOKIE}),
        principals=frozenset({"user"}),
    )
    assert scenario.status is ScenarioStatus.PLANNED


def test_logout_invalidation_confirmed(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("session.logout-invalidation")
    transport = transport_factory(_make_logout_vuln())
    result = run_scenario(pb, transport, {"user": True})
    checks.confirmed(result)
    checks.cleanup(result)
    # All three requests reused the single user session on the wire ...
    assert transport.cookie_for("user") == {"sess_user=user-secret-token"}
    # ... yet the session secret never reached the evidence (SI-3).
    checks.absent(result, "user-secret-token", "user-bearer-not-real")


def test_logout_invalidation_rejected_when_enforced(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("session.logout-invalidation")
    result = run_scenario(pb, transport_factory(_make_logout_secure()), {"user": True})
    checks.rejected(result)
