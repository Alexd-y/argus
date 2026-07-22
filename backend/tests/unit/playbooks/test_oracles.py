"""Tests for the deterministic scenario oracles."""

from __future__ import annotations

import json

import pytest

from src.playbooks.actions import HttpExchange, HttpRequestSpec, HttpResponse
from src.playbooks.oracles import (
    OracleNotImplemented,
    OracleVerdict,
    get_oracle,
    validate_params,
)
from src.playbooks.schema import HttpMethod, OracleType


def _exchange(status: int, body: str = "", headers: dict[str, str] | None = None) -> HttpExchange:
    return HttpExchange(
        request=HttpRequestSpec(method=HttpMethod.GET, url="https://target/api/x"),
        response=HttpResponse(status=status, body=body, headers=headers or {}),
    )


# ---------------------------------------------------------------------------
# authz
# ---------------------------------------------------------------------------


def test_authz_identical_data_is_finding() -> None:
    victim = {"id": 7, "email": "victim@example.com", "account_number": "AC-7"}
    baseline = _exchange(200, json.dumps(victim))
    mutated = _exchange(200, json.dumps(victim))
    result = get_oracle(OracleType.AUTHZ).evaluate(baseline, mutated, {})
    assert result.verdict is OracleVerdict.FINDING


def test_authz_sensitive_field_match_is_finding() -> None:
    baseline = _exchange(200, json.dumps({"email": "victim@example.com", "id": 7}))
    mutated = _exchange(200, json.dumps({"email": "victim@example.com", "id": 7}))
    result = get_oracle(OracleType.AUTHZ).evaluate(
        baseline, mutated, {"sensitive_fields": ["email"]}
    )
    assert result.verdict is OracleVerdict.FINDING
    assert "email" in result.reason


def test_authz_timestamp_only_diff_is_not_finding() -> None:
    baseline = _exchange(200, json.dumps({"id": 7, "email": "v@x.com", "updated_at": "2026-01-01"}))
    mutated = _exchange(200, json.dumps({"id": 7, "email": "v@x.com", "updated_at": "2026-07-22"}))
    result = get_oracle(OracleType.AUTHZ).evaluate(baseline, mutated, {})
    assert result.verdict is OracleVerdict.NO_FINDING
    assert result.differing_fields == ["updated_at"]


def test_authz_denied_is_not_finding() -> None:
    baseline = _exchange(200, json.dumps({"email": "v@x.com"}))
    mutated = _exchange(403, "forbidden")
    result = get_oracle(OracleType.AUTHZ).evaluate(baseline, mutated, {})
    assert result.verdict is OracleVerdict.NO_FINDING


def test_authz_substantive_diff_is_not_finding() -> None:
    baseline = _exchange(200, json.dumps({"id": 7, "email": "victim@x.com"}))
    mutated = _exchange(200, json.dumps({"id": 99, "email": "attacker@x.com"}))
    result = get_oracle(OracleType.AUTHZ).evaluate(baseline, mutated, {})
    assert result.verdict is OracleVerdict.NO_FINDING


def test_authz_200_alone_is_not_proof() -> None:
    # Attacker gets 200 but with their own (different) data — not an IDOR.
    baseline = _exchange(200, json.dumps({"email": "victim@x.com"}))
    mutated = _exchange(200, json.dumps({"email": "attacker@x.com"}))
    result = get_oracle(OracleType.AUTHZ).evaluate(
        baseline, mutated, {"sensitive_fields": ["email"]}
    )
    assert result.verdict is OracleVerdict.NO_FINDING


# ---------------------------------------------------------------------------
# rate_limit
# ---------------------------------------------------------------------------


def test_rate_limit_no_429_single_request_is_inconclusive() -> None:
    baseline = _exchange(200, "ok")
    mutated = _exchange(200, "ok")
    result = get_oracle(OracleType.RATE_LIMIT).evaluate(baseline, mutated, {})
    assert result.verdict is OracleVerdict.INCONCLUSIVE
    assert result.verdict is not OracleVerdict.FINDING


def test_rate_limit_throttled_is_not_finding() -> None:
    baseline = _exchange(200, "ok")
    mutated = _exchange(429, "slow down", headers={"Retry-After": "30"})
    result = get_oracle(OracleType.RATE_LIMIT).evaluate(baseline, mutated, {})
    assert result.verdict is OracleVerdict.NO_FINDING


def test_rate_limit_burst_without_throttle_is_finding() -> None:
    baseline = _exchange(200, "ok")
    mutated = _exchange(200, "ok")
    params = {"threshold": 20, "observed_statuses": [200] * 25}
    result = get_oracle(OracleType.RATE_LIMIT).evaluate(baseline, mutated, params)
    assert result.verdict is OracleVerdict.FINDING


def test_rate_limit_burst_with_throttle_is_not_finding() -> None:
    baseline = _exchange(200, "ok")
    mutated = _exchange(200, "ok")
    params = {"threshold": 20, "observed_statuses": [200] * 24 + [429]}
    result = get_oracle(OracleType.RATE_LIMIT).evaluate(baseline, mutated, params)
    assert result.verdict is OracleVerdict.NO_FINDING


# ---------------------------------------------------------------------------
# authn
# ---------------------------------------------------------------------------


def test_authn_denied_is_not_finding() -> None:
    baseline = _exchange(200, json.dumps({"data": 1}))
    mutated = _exchange(401, "unauthorized")
    result = get_oracle(OracleType.AUTHN).evaluate(baseline, mutated, {})
    assert result.verdict is OracleVerdict.NO_FINDING


def test_authn_unauth_success_is_finding() -> None:
    baseline = _exchange(200, json.dumps({"data": 1}))
    mutated = _exchange(200, json.dumps({"data": 1}))
    result = get_oracle(OracleType.AUTHN).evaluate(baseline, mutated, {})
    assert result.verdict is OracleVerdict.FINDING


# ---------------------------------------------------------------------------
# params validation
# ---------------------------------------------------------------------------


def test_validate_params_rejects_unknown_key() -> None:
    with pytest.raises(ValueError):
        validate_params(OracleType.AUTHZ, {"bogus": 1})


def test_race_oracle_rejects_unknown_param() -> None:
    with pytest.raises(ValueError):
        validate_params(OracleType.RACE, {"anything": 1})
    # empty params accepted (all fields optional with defaults)
    validate_params(OracleType.RACE, {})


def test_oracle_not_implemented_symbol_is_still_importable() -> None:
    # Legacy back-compat export; no oracle raises it anymore.
    assert issubclass(OracleNotImplemented, NotImplementedError)


# ---------------------------------------------------------------------------
# race
# ---------------------------------------------------------------------------


def test_race_state_delta_over_invariant_is_finding() -> None:
    before = _exchange(200, json.dumps({"balance": 100}))
    after = _exchange(200, json.dumps({"balance": 500}))
    params = {"state_field": "balance", "expected_max_success": 100, "success_count": 5}
    result = get_oracle(OracleType.RACE).evaluate(before, after, params)
    assert result.verdict is OracleVerdict.FINDING


def test_race_no_real_state_change_is_not_finding() -> None:
    before = _exchange(200, json.dumps({"redeemed": 1}))
    after = _exchange(200, json.dumps({"redeemed": 1}))
    params = {"state_field": "redeemed", "expected_max_success": 1, "success_count": 8}
    result = get_oracle(OracleType.RACE).evaluate(before, after, params)
    assert result.verdict is OracleVerdict.NO_FINDING


def test_race_without_state_field_uses_success_count() -> None:
    baseline = _exchange(200, "")
    mutated = _exchange(200, "")
    finding = get_oracle(OracleType.RACE).evaluate(
        baseline, mutated, {"expected_max_success": 1, "observed_statuses": [200, 200, 201]}
    )
    assert finding.verdict is OracleVerdict.FINDING
    clean = get_oracle(OracleType.RACE).evaluate(
        baseline, mutated, {"expected_max_success": 1, "observed_statuses": [200, 429, 429]}
    )
    assert clean.verdict is OracleVerdict.NO_FINDING


def test_race_unreadable_state_is_inconclusive() -> None:
    before = _exchange(200, "not json")
    after = _exchange(200, "not json")
    result = get_oracle(OracleType.RACE).evaluate(
        before, after, {"state_field": "balance"}
    )
    assert result.verdict is OracleVerdict.INCONCLUSIVE


# ---------------------------------------------------------------------------
# file_upload
# ---------------------------------------------------------------------------


def test_file_upload_marker_served_is_finding() -> None:
    upload = _exchange(201, "created")
    fetch = _exchange(200, "prefix ARGUS-MARKER-9f3 suffix")
    result = get_oracle(OracleType.FILE_UPLOAD).evaluate(
        upload, fetch, {"marker": "ARGUS-MARKER-9f3"}
    )
    assert result.verdict is OracleVerdict.FINDING


def test_file_upload_denied_fetch_is_not_finding() -> None:
    upload = _exchange(201, "created")
    fetch = _exchange(403, "forbidden")
    result = get_oracle(OracleType.FILE_UPLOAD).evaluate(
        upload, fetch, {"marker": "ARGUS-MARKER-9f3"}
    )
    assert result.verdict is OracleVerdict.NO_FINDING


def test_file_upload_marker_absent_is_not_finding() -> None:
    upload = _exchange(201, "created")
    fetch = _exchange(200, "some other content")
    result = get_oracle(OracleType.FILE_UPLOAD).evaluate(
        upload, fetch, {"marker": "ARGUS-MARKER-9f3"}
    )
    assert result.verdict is OracleVerdict.NO_FINDING


# ---------------------------------------------------------------------------
# business_logic
# ---------------------------------------------------------------------------


def test_business_logic_unchanged_invariant_violated_is_finding() -> None:
    before = _exchange(200, json.dumps({"balance": 100}))
    after = _exchange(200, json.dumps({"balance": 250}))
    result = get_oracle(OracleType.BUSINESS_LOGIC).evaluate(
        before, after, {"field": "balance", "relation": "unchanged"}
    )
    assert result.verdict is OracleVerdict.FINDING


def test_business_logic_unchanged_invariant_held_is_not_finding() -> None:
    before = _exchange(200, json.dumps({"balance": 100}))
    after = _exchange(200, json.dumps({"balance": 100}))
    result = get_oracle(OracleType.BUSINESS_LOGIC).evaluate(
        before, after, {"field": "balance", "relation": "unchanged"}
    )
    assert result.verdict is OracleVerdict.NO_FINDING


def test_business_logic_non_decreasing_violation_is_finding() -> None:
    before = _exchange(200, json.dumps({"stock": 5}))
    after = _exchange(200, json.dumps({"stock": 2}))
    result = get_oracle(OracleType.BUSINESS_LOGIC).evaluate(
        before, after, {"field": "stock", "relation": "non_decreasing"}
    )
    assert result.verdict is OracleVerdict.FINDING


def test_business_logic_unreadable_field_is_inconclusive() -> None:
    before = _exchange(200, json.dumps({"other": 1}))
    after = _exchange(200, json.dumps({"other": 2}))
    result = get_oracle(OracleType.BUSINESS_LOGIC).evaluate(
        before, after, {"field": "balance", "relation": "unchanged"}
    )
    assert result.verdict is OracleVerdict.INCONCLUSIVE
