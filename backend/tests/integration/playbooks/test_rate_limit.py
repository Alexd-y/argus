"""P5 integration tests: rate-limit playbooks end-to-end on a stub target.

Covers ``ratelimit.login-account-keyed`` (missing per-account brute-force
throttling) and ``ratelimit.otp-resend`` (unthrottled OTP resend). A burst with
no throttling confirms a finding; a target that throttles the final request
(429 / Retry-After) yields no finding. Request passwords and leaked OTPs are
redacted in the evidence (SI-3).
"""

from __future__ import annotations

import json
from collections.abc import Callable

from src.playbooks.actions import HttpRequestSpec, HttpResponse
from src.playbooks.lifecycle import ScenarioStatus
from src.playbooks.schema import HttpMethod, InputKind, Playbook

# ---------------------------------------------------------------------------
# ratelimit.login-account-keyed
# ---------------------------------------------------------------------------


def _login_vuln(_spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
    # Broken: no per-account throttling; every attempt is answered 401.
    return HttpResponse(status=401, body='{"error":"bad_credentials"}')


def _make_login_secure() -> Callable[[HttpRequestSpec, "str | None"], HttpResponse]:
    state = {"n": 0}

    def _r(_spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
        state["n"] += 1
        if state["n"] >= 2:
            return HttpResponse(
                status=429, body='{"error":"rate_limited"}', headers={"Retry-After": "60"}
            )
        return HttpResponse(status=401, body='{"error":"bad_credentials"}')

    return _r


def test_login_rate_limit_is_planned(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    scenario = plan_pb(
        get_playbook("ratelimit.login-account-keyed"),
        method=HttpMethod.POST,
        path="/api/v1/login",
        input_kinds=frozenset({InputKind.BODY_JSON}),
        principals=frozenset({"attacker"}),
    )
    assert scenario.status is ScenarioStatus.PLANNED


def test_login_rate_limit_confirmed(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("ratelimit.login-account-keyed")
    result = run_scenario(pb, transport_factory(_login_vuln), {"attacker": True})
    checks.confirmed(result)
    checks.cleanup(result)
    # The guessed password in the login body is redacted in evidence.
    checks.redacted(result, "guess-1-not-real")


def test_login_rate_limit_rejected_when_throttled(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("ratelimit.login-account-keyed")
    result = run_scenario(pb, transport_factory(_make_login_secure()), {"attacker": True})
    checks.rejected(result)


# ---------------------------------------------------------------------------
# ratelimit.otp-resend
# ---------------------------------------------------------------------------


def _otp_vuln(_spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
    # Broken: unbounded resend; the response even leaks the code.
    return HttpResponse(status=200, body=json.dumps({"status": "sent", "otp": "123456"}))


def _make_otp_secure() -> Callable[[HttpRequestSpec, "str | None"], HttpResponse]:
    state = {"n": 0}

    def _r(_spec: HttpRequestSpec, _principal: str | None) -> HttpResponse:
        state["n"] += 1
        if state["n"] >= 2:
            return HttpResponse(
                status=429, body='{"error":"rate_limited"}', headers={"Retry-After": "30"}
            )
        return HttpResponse(status=200, body=json.dumps({"status": "sent"}))

    return _r


def test_otp_resend_is_planned(
    get_playbook: Callable[[str], Playbook],
    plan_pb: Callable[..., object],
) -> None:
    scenario = plan_pb(
        get_playbook("ratelimit.otp-resend"),
        method=HttpMethod.POST,
        path="/api/v1/otp/resend",
        input_kinds=frozenset({InputKind.BODY_JSON}),
        principals=frozenset({"user"}),
    )
    assert scenario.status is ScenarioStatus.PLANNED


def test_otp_resend_confirmed(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("ratelimit.otp-resend")
    result = run_scenario(pb, transport_factory(_otp_vuln), {"user": True})
    checks.confirmed(result)
    checks.cleanup(result)
    # The leaked OTP in the response body is redacted in evidence.
    checks.redacted(result, "123456")


def test_otp_resend_rejected_when_throttled(
    get_playbook: Callable[[str], Playbook],
    transport_factory: Callable[..., object],
    run_scenario: Callable[..., object],
    checks: object,
) -> None:
    pb = get_playbook("ratelimit.otp-resend")
    result = run_scenario(pb, transport_factory(_make_otp_secure()), {"user": True})
    checks.rejected(result)
