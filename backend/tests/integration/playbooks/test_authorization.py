"""P5 integration tests: authorization playbooks end-to-end on a stub target.

Covers ``idor.cross-user-read`` (BOLA read), the approval-gated
``idor.cross-user-write`` (BOLA write), ``authorization.method-variant`` (verb
tampering) and the approval-gated ``massassignment.role-injection`` (privilege
escalation). Proves >=2 isolated principal sessions for IDOR and both approval
paths (SI-1) for the gated write/mass-assignment scenarios.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from src.playbooks.actions import HttpRequestSpec, HttpResponse
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.schema import HttpMethod, InputKind, Playbook
from src.policy.engagement_authorization import ActionClass

_VICTIM = {
    "id": 2001,
    "email": "victim@example.test",
    "account_number": "ACCT-000999",
    "phone": "+10000000000",
}
_ATTACKER_OWN = {
    "id": 4002,
    "email": "attacker@example.test",
    "account_number": "ACCT-004002",
    "phone": "+19999999999",
}
_ADMIN_REC = {"id": 5, "email": "admin@example.test", "role": "admin"}


# ---------------------------------------------------------------------------
# idor.cross-user-read
# ---------------------------------------------------------------------------


def _idor_vuln(_spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
    # Broken: both principals receive the victim's record.
    return HttpResponse(status=200, body=json.dumps(_VICTIM))


def _idor_secure(_spec: HttpRequestSpec, principal: str | None) -> HttpResponse:
    if principal == "attacker":
        return HttpResponse(status=403, body='{"error":"forbidden"}')
    return HttpResponse(status=200, body=json.dumps(_VICTIM))


def _idor_own_data(_spec: HttpRequestSpec, principal: str | None) -> HttpResponse:
    # Not-vulnerable: the attacker only ever sees their own (different) record.
    if principal == "attacker":
        return HttpResponse(status=200, body=json.dumps(_ATTACKER_OWN))
    return HttpResponse(status=200, body=json.dumps(_VICTIM))


def test_idor_read_is_planned(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    scenario = plan_pb(
        get_playbook("idor.cross-user-read"),
        method=HttpMethod.GET,
        path="/api/v1/users/2001",
        input_kinds=frozenset({InputKind.PATH_PARAM}),
        principals=frozenset({"owner", "attacker"}),
    )
    assert scenario.status is ScenarioStatus.PLANNED


def test_idor_read_confirmed_with_isolated_sessions(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("idor.cross-user-read")
    transport = transport_factory(_idor_vuln)
    result = run_scenario(pb, transport, {"owner": True, "attacker": True})
    checks.confirmed(result)
    checks.cleanup(result)
    # Proof of >=2 isolated sessions: owner and attacker used distinct cookies.
    owner_cookies = transport.cookie_for("owner")
    attacker_cookies = transport.cookie_for("attacker")
    assert owner_cookies == {"sess_owner=owner-secret-token"}
    assert attacker_cookies == {"sess_attacker=attacker-secret-token"}
    assert owner_cookies.isdisjoint(attacker_cookies)
    checks.absent(result, "owner-secret-token", "attacker-secret-token")


def test_idor_read_rejected_when_denied(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("idor.cross-user-read")
    result = run_scenario(pb, transport_factory(_idor_secure), {"owner": True, "attacker": True})
    checks.rejected(result)


def test_idor_read_no_finding_when_attacker_sees_own_data(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("idor.cross-user-read")
    result = run_scenario(pb, transport_factory(_idor_own_data), {"owner": True, "attacker": True})
    checks.rejected(result)


# ---------------------------------------------------------------------------
# idor.cross-user-write (approval-gated: account_mutation / data write)
# ---------------------------------------------------------------------------


def _idorw_vuln(spec: HttpRequestSpec, principal: str | None) -> HttpResponse:
    if principal == "attacker" and spec.method.value == "PUT":
        # Broken: attacker's write to the victim's object succeeds and echoes it.
        return HttpResponse(
            status=200,
            body=json.dumps(
                {"id": 2001, "email": "victim@example.test", "display_name": "pwned-by-attacker"}
            ),
        )
    return HttpResponse(
        status=200,
        body=json.dumps({"id": 2001, "email": "victim@example.test", "display_name": "Victim"}),
    )


def _idorw_secure(spec: HttpRequestSpec, principal: str | None) -> HttpResponse:
    if principal == "attacker":
        return HttpResponse(status=403, body='{"error":"forbidden"}')
    return HttpResponse(
        status=200,
        body=json.dumps({"id": 2001, "email": "victim@example.test", "display_name": "Victim"}),
    )


def test_idor_write_planning_routes_by_approval(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    pb = get_playbook("idor.cross-user-write")
    kwargs = dict(
        method=HttpMethod.GET,
        path="/api/v1/users/2001/profile",
        input_kinds=frozenset({InputKind.PATH_PARAM, InputKind.BODY_JSON}),
        principals=frozenset({"owner", "attacker"}),
    )
    assert plan_pb(pb, **kwargs).status is ScenarioStatus.WAITING_APPROVAL
    assert plan_pb(pb, is_preauthorized=lambda _pb: True, **kwargs).status is ScenarioStatus.PLANNED


def test_idor_write_waiting_approval_without_eap(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
) -> None:
    pb = get_playbook("idor.cross-user-write")
    transport = transport_factory(_idorw_vuln)
    result = run_scenario(pb, transport, {"owner": True, "attacker": True})
    assert result.executed is False
    assert result.state.status is ScenarioStatus.WAITING_APPROVAL
    assert transport.calls == []


def test_idor_write_confirmed_with_eap(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    eap_gate_factory: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("idor.cross-user-write")
    gate = eap_gate_factory(
        frozenset({ActionClass.ACCOUNT_MUTATION}), action_class=ActionClass.ACCOUNT_MUTATION
    )
    result = run_scenario(
        pb, transport_factory(_idorw_vuln), {"owner": True, "attacker": True}, gate=gate
    )
    checks.confirmed(result)
    checks.cleanup(result)
    assert result.approval_id is not None


def test_idor_write_denied_by_eap_missing_class(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    eap_gate_factory: Callable[..., object],
) -> None:
    pb = get_playbook("idor.cross-user-write")
    # EAP pre-authorizes a different class -> the gate denies (SI-1).
    gate = eap_gate_factory(
        frozenset({ActionClass.RECON}), action_class=ActionClass.ACCOUNT_MUTATION
    )
    transport = transport_factory(_idorw_vuln)
    result = run_scenario(pb, transport, {"owner": True, "attacker": True}, gate=gate)
    assert result.executed is False
    assert result.state.status is ScenarioStatus.WAITING_APPROVAL
    assert transport.calls == []


def test_idor_write_rejected_when_denied(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    eap_gate_factory: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("idor.cross-user-write")
    gate = eap_gate_factory(
        frozenset({ActionClass.ACCOUNT_MUTATION}), action_class=ActionClass.ACCOUNT_MUTATION
    )
    result = run_scenario(
        pb, transport_factory(_idorw_secure), {"owner": True, "attacker": True}, gate=gate
    )
    checks.rejected(result)


# ---------------------------------------------------------------------------
# authorization.method-variant
# ---------------------------------------------------------------------------


def _mv_vuln(_spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
    # Broken: the method variant skips the authorization check.
    return HttpResponse(status=200, body=json.dumps(_ADMIN_REC))


def _mv_secure(_spec: HttpRequestSpec, principal: str | None) -> HttpResponse:
    if principal == "attacker":
        return HttpResponse(status=403, body='{"error":"forbidden"}')
    return HttpResponse(status=200, body=json.dumps(_ADMIN_REC))


def test_method_variant_is_planned(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    scenario = plan_pb(
        get_playbook("authorization.method-variant"),
        method=HttpMethod.GET,
        path="/api/v1/admin/users/5",
        input_kinds=frozenset({InputKind.HEADER}),
        principals=frozenset({"admin", "attacker"}),
    )
    assert scenario.status is ScenarioStatus.PLANNED


def test_method_variant_confirmed(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("authorization.method-variant")
    result = run_scenario(pb, transport_factory(_mv_vuln), {"admin": True, "attacker": True})
    checks.confirmed(result)
    checks.cleanup(result)


def test_method_variant_rejected_when_denied(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("authorization.method-variant")
    result = run_scenario(pb, transport_factory(_mv_secure), {"admin": True, "attacker": True})
    checks.rejected(result)


# ---------------------------------------------------------------------------
# massassignment.role-injection (approval-gated: account_mutation)
# ---------------------------------------------------------------------------


def _make_ma_vuln() -> Callable[[HttpRequestSpec, "str | None"], HttpResponse]:
    state = {"role": "user"}

    def _r(spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
        if spec.method.value == "PATCH":
            body = spec.body or ""
            if '"role":"admin"' in body:
                state["role"] = "admin"  # Broken: injected role is bound.
            elif '"role":"user"' in body:
                state["role"] = "user"
            return HttpResponse(status=200, body=json.dumps({"status": "updated"}))
        return HttpResponse(status=200, body=json.dumps({"id": 42, "role": state["role"]}))

    return _r


def _make_ma_secure() -> Callable[[HttpRequestSpec, "str | None"], HttpResponse]:
    def _r(spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
        if spec.method.value == "PATCH":
            # Secure: the server ignores the unexpected privileged attribute.
            return HttpResponse(status=200, body=json.dumps({"status": "updated"}))
        return HttpResponse(status=200, body=json.dumps({"id": 42, "role": "user"}))

    return _r


def test_mass_assignment_planning_routes_by_approval(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    pb = get_playbook("massassignment.role-injection")
    kwargs = dict(
        method=HttpMethod.GET,
        path="/api/v1/users/me",
        input_kinds=frozenset({InputKind.BODY_JSON}),
        principals=frozenset({"user"}),
    )
    assert plan_pb(pb, **kwargs).status is ScenarioStatus.WAITING_APPROVAL
    assert plan_pb(pb, is_preauthorized=lambda _pb: True, **kwargs).status is ScenarioStatus.PLANNED


def test_mass_assignment_waiting_approval_without_eap(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
) -> None:
    pb = get_playbook("massassignment.role-injection")
    transport = transport_factory(_make_ma_vuln())
    result = run_scenario(pb, transport, {"user": True})
    assert result.executed is False
    assert result.state.status is ScenarioStatus.WAITING_APPROVAL
    assert transport.calls == []


def test_mass_assignment_confirmed_with_eap(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    eap_gate_factory: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("massassignment.role-injection")
    gate = eap_gate_factory(
        frozenset({ActionClass.ACCOUNT_MUTATION}), action_class=ActionClass.ACCOUNT_MUTATION
    )
    result = run_scenario(pb, transport_factory(_make_ma_vuln()), {"user": True}, gate=gate)
    checks.confirmed(result)
    checks.cleanup(result)
    assert result.approval_id is not None


def test_mass_assignment_rejected_when_enforced(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    eap_gate_factory: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("massassignment.role-injection")
    gate = eap_gate_factory(
        frozenset({ActionClass.ACCOUNT_MUTATION}), action_class=ActionClass.ACCOUNT_MUTATION
    )
    result = run_scenario(pb, transport_factory(_make_ma_secure()), {"user": True}, gate=gate)
    checks.rejected(result)
