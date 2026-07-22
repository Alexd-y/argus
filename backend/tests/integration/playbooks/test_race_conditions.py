"""P5 integration test: race-condition playbook end-to-end on a stub target.

``race.single-use-token`` is approval-gated (race class). It reads the server
side redemption counter, fires concurrent redemptions of one single-use token,
and re-reads the counter. The race oracle confirms only when the server state
advanced by more than the idempotency invariant allows (>1) - a pile of 2xx
responses alone is never proof. Proves SI-1 on both approval paths.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from src.playbooks.actions import HttpRequestSpec, HttpResponse
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.schema import HttpMethod, InputKind, Playbook
from src.policy.engagement_authorization import ActionClass


def _make_race_vuln() -> Callable[[HttpRequestSpec, "str | None"], HttpResponse]:
    state = {"redemptions": 0}

    def _r(spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
        if spec.method.value == "GET":
            return HttpResponse(status=200, body=json.dumps({"redemptions": state["redemptions"]}))
        if spec.method.value == "POST":
            # Broken: check-then-act is not atomic; every concurrent hit applies.
            state["redemptions"] += 1
            return HttpResponse(status=200, body=json.dumps({"status": "redeemed"}))
        return HttpResponse(status=204, body="")  # cleanup DELETE

    return _r


def _make_race_secure() -> Callable[[HttpRequestSpec, "str | None"], HttpResponse]:
    state = {"redemptions": 0, "used": False}

    def _r(spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
        if spec.method.value == "GET":
            return HttpResponse(status=200, body=json.dumps({"redemptions": state["redemptions"]}))
        if spec.method.value == "POST":
            if not state["used"]:
                state["used"] = True
                state["redemptions"] = 1
                return HttpResponse(status=200, body=json.dumps({"status": "redeemed"}))
            return HttpResponse(status=409, body=json.dumps({"error": "already_redeemed"}))
        return HttpResponse(status=204, body="")

    return _r


def test_race_planning_routes_by_approval(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    pb = get_playbook("race.single-use-token")
    kwargs = dict(
        method=HttpMethod.POST,
        path="/api/v1/redeem",
        input_kinds=frozenset({InputKind.BODY_JSON}),
        principals=frozenset({"attacker"}),
    )
    assert plan_pb(pb, **kwargs).status is ScenarioStatus.WAITING_APPROVAL
    assert plan_pb(pb, is_preauthorized=lambda _pb: True, **kwargs).status is ScenarioStatus.PLANNED


def test_race_waiting_approval_without_eap(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
) -> None:
    pb = get_playbook("race.single-use-token")
    transport = transport_factory(_make_race_vuln())
    result = run_scenario(pb, transport, {"attacker": True})
    assert result.executed is False
    assert result.state.status is ScenarioStatus.WAITING_APPROVAL
    assert transport.calls == []


def test_race_confirmed_with_eap(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    eap_gate_factory: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("race.single-use-token")
    gate = eap_gate_factory(frozenset({ActionClass.RACE}))
    result = run_scenario(pb, transport_factory(_make_race_vuln()), {"attacker": True}, gate=gate)
    checks.confirmed(result)
    checks.cleanup(result)
    assert result.approval_id is not None
    # The race oracle proved >1 redemption via server-side state, not 2xx count.
    race_results = [r for r in result.oracle_results if r.is_finding]
    assert race_results and "state changed" in race_results[0].reason


def test_race_rejected_when_single_use_enforced(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    eap_gate_factory: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("race.single-use-token")
    gate = eap_gate_factory(frozenset({ActionClass.RACE}))
    result = run_scenario(pb, transport_factory(_make_race_secure()), {"attacker": True}, gate=gate)
    checks.rejected(result)
