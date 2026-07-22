"""P5 integration tests: account-lifecycle playbooks end-to-end on a stub target.

Covers ``registration.duplicate-casefold`` (case-fold uniqueness bypass) and the
approval-gated ``reset.token-reuse-after-password-change`` (single-use reset
token replay). The reset playbook proves SI-1 on both paths: WAITING_APPROVAL
without an EAP, executed once an EAP pre-authorizes the ``account_mutation``
class + target.
"""

from __future__ import annotations

import json
from collections.abc import Callable

from src.playbooks.actions import HttpRequestSpec, HttpResponse
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.schema import HttpMethod, InputKind, Playbook
from src.policy.engagement_authorization import ActionClass

# ---------------------------------------------------------------------------
# registration.duplicate-casefold
# ---------------------------------------------------------------------------


def _reg_vuln(spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
    # Broken: the case-fold variant is accepted as a brand-new identity.
    if "ADMIN@" in (spec.body or ""):
        return HttpResponse(
            status=201, body=json.dumps({"registration_status": "created", "user_id": 2})
        )
    return HttpResponse(
        status=201, body=json.dumps({"registration_status": "created", "user_id": 1})
    )


def _reg_secure(spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
    if "ADMIN@" in (spec.body or ""):
        return HttpResponse(
            status=409, body=json.dumps({"registration_status": "duplicate_rejected"})
        )
    return HttpResponse(
        status=201, body=json.dumps({"registration_status": "created", "user_id": 1})
    )


def test_registration_casefold_is_planned(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    scenario = plan_pb(
        get_playbook("registration.duplicate-casefold"),
        method=HttpMethod.POST,
        path="/api/v1/register",
        input_kinds=frozenset({InputKind.BODY_JSON}),
        principals=frozenset({"anon"}),
    )
    assert scenario.status is ScenarioStatus.PLANNED


def test_registration_casefold_confirmed(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("registration.duplicate-casefold")
    result = run_scenario(pb, transport_factory(_reg_vuln), {"anon": False})
    checks.confirmed(result)
    checks.cleanup(result)
    # The registration password submitted in the request body is redacted.
    checks.redacted(result, "P4ssw0rd-not-real")


def test_registration_casefold_rejected_when_enforced(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("registration.duplicate-casefold")
    result = run_scenario(pb, transport_factory(_reg_secure), {"anon": False})
    checks.rejected(result)


# ---------------------------------------------------------------------------
# reset.token-reuse-after-password-change (approval-gated: account_mutation)
# ---------------------------------------------------------------------------


def _make_reset_vuln() -> Callable[[HttpRequestSpec, "str | None"], HttpResponse]:
    state = {"posts": 0}

    def _r(spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
        if spec.method.value == "POST":
            state["posts"] += 1
            if state["posts"] == 1:
                return HttpResponse(status=200, body=json.dumps({"status": "password_updated"}))
            # Broken: the single-use token is still accepted on reuse.
            return HttpResponse(status=200, body=json.dumps({"status": "password_updated_again"}))
        return HttpResponse(status=204, body="")  # cleanup DELETE

    return _r


def _make_reset_secure() -> Callable[[HttpRequestSpec, "str | None"], HttpResponse]:
    state = {"posts": 0}

    def _r(spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
        if spec.method.value == "POST":
            state["posts"] += 1
            if state["posts"] == 1:
                return HttpResponse(status=200, body=json.dumps({"status": "password_updated"}))
            return HttpResponse(status=400, body=json.dumps({"error": "token_expired"}))
        return HttpResponse(status=204, body="")

    return _r


def test_reset_token_reuse_planning_routes_by_approval(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    pb = get_playbook("reset.token-reuse-after-password-change")
    kwargs = dict(
        method=HttpMethod.POST,
        path="/api/v1/password/reset",
        input_kinds=frozenset({InputKind.BODY_JSON}),
        principals=frozenset({"victim"}),
    )
    # No EAP on file -> routed to WAITING_APPROVAL (never a silent skip).
    waiting = plan_pb(pb, **kwargs)
    assert waiting.status is ScenarioStatus.WAITING_APPROVAL
    # Pre-authorized by an EAP -> PLANNED.
    planned = plan_pb(pb, is_preauthorized=lambda _pb: True, **kwargs)
    assert planned.status is ScenarioStatus.PLANNED


def test_reset_token_reuse_waiting_approval_without_eap(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
) -> None:
    pb = get_playbook("reset.token-reuse-after-password-change")
    transport = transport_factory(_make_reset_vuln())
    result = run_scenario(pb, transport, {"victim": True})
    # SI-1: an approval-gated playbook with no gate never runs.
    assert result.executed is False
    assert result.state.status is ScenarioStatus.WAITING_APPROVAL
    assert transport.calls == []


def test_reset_token_reuse_confirmed_with_eap(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    eap_gate_factory: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("reset.token-reuse-after-password-change")
    gate = eap_gate_factory(frozenset({ActionClass.ACCOUNT_MUTATION}))
    result = run_scenario(pb, transport_factory(_make_reset_vuln()), {"victim": True}, gate=gate)
    checks.confirmed(result)
    checks.cleanup(result)
    assert result.approval_id is not None
    # The reset token + new password from the request bodies are redacted.
    checks.redacted(result, "reset-token-test-fixture", "Rotated-1-not-real")


def test_reset_token_reuse_rejected_when_enforced(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    eap_gate_factory: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("reset.token-reuse-after-password-change")
    gate = eap_gate_factory(frozenset({ActionClass.ACCOUNT_MUTATION}))
    result = run_scenario(pb, transport_factory(_make_reset_secure()), {"victim": True}, gate=gate)
    checks.rejected(result)
