"""Phase 4 — agent output contract validators + JSON schemas."""

from __future__ import annotations

import pytest
from src.cairn.contracts import (
    JSON_SCHEMA_CAIRN_BOOTSTRAP,
    JSON_SCHEMA_CAIRN_EXPLORE,
    JSON_SCHEMA_CAIRN_REASON,
    validate_bootstrap_conclude_payload,
    validate_bootstrap_execute_payload,
    validate_explore_payload,
    validate_reason_payload,
)

# --- reason ------------------------------------------------------------------


def test_reason_rejected_envelope() -> None:
    kind, data = validate_reason_payload({"accepted": False, "reason": "policy"}, False, 3)
    assert kind == "rejected"
    assert data is None


def test_reason_complete() -> None:
    payload = {"complete": {"from": ["f1"], "description": "goal reached"}}
    kind, data = validate_reason_payload(payload, False, 3)
    assert kind == "complete"
    assert data == {"from": ["f1"], "description": "goal reached"}


def test_reason_intents() -> None:
    payload = {"intents": [{"from": ["origin"], "description": "a"}]}
    kind, data = validate_reason_payload(payload, True, 3)
    assert kind == "intents"
    assert isinstance(data, list) and len(data) == 1


def test_reason_singular_intent_promoted() -> None:
    payload = {"intent": {"from": ["origin"], "description": "a"}}
    kind, data = validate_reason_payload(payload, False, 3)
    assert kind == "intents"
    assert isinstance(data, list) and len(data) == 1


def test_reason_complete_and_intents_conflict() -> None:
    # Structural coexist error is reached via the wrapped envelope; a bare payload
    # with an unrecognised shape is rejected earlier as "accepted must be ...".
    payload = {
        "accepted": True,
        "data": {"complete": {"from": ["f1"], "description": "x"}, "intents": []},
    }
    with pytest.raises(ValueError, match="cannot coexist"):
        validate_reason_payload(payload, False, 3)


def test_reason_empty_intents_when_open_empty_raises() -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        validate_reason_payload({"intents": []}, True, 3)


def test_reason_truncates_to_max_intents() -> None:
    payload = {"intents": [{"from": ["o"], "description": str(i)} for i in range(10)]}
    kind, data = validate_reason_payload(payload, True, 3)
    assert kind == "intents"
    assert isinstance(data, list) and len(data) == 3


def test_reason_noop_when_nothing_and_open_not_empty() -> None:
    kind, data = validate_reason_payload({"intents": []}, False, 3)
    assert kind == "noop"
    assert data is None


def test_reason_wrapped_accepted_true_unwraps_data() -> None:
    payload = {"accepted": True, "data": {"intents": [{"from": ["o"], "description": "a"}]}}
    kind, data = validate_reason_payload(payload, True, 3)
    assert kind == "intents"


def test_reason_invalid_intent_index_message() -> None:
    payload = {"intents": [{"from": ["o"], "description": "a"}, {"description": "b"}]}
    with pytest.raises(ValueError, match="invalid intent at index 1"):
        validate_reason_payload(payload, True, 3)


def test_reason_intents_required_when_open_empty_and_no_keys() -> None:
    payload = {"accepted": True, "data": {}}
    with pytest.raises(ValueError, match="required when open_intents is empty"):
        validate_reason_payload(payload, True, 3)


def test_reason_bare_unrecognised_shape_rejected() -> None:
    with pytest.raises(ValueError, match="accepted must be true or false"):
        validate_reason_payload({"foo": "bar"}, True, 3)


# --- bootstrap execute -------------------------------------------------------


def test_bootstrap_execute_requires_both_descriptions() -> None:
    payload = {"fact": {"description": "f"}, "complete": {"description": "c"}}
    kind, data = validate_bootstrap_execute_payload(payload)
    assert kind == "complete"
    assert data == {"fact_description": "f", "complete_description": "c"}


def test_bootstrap_execute_missing_complete_raises() -> None:
    payload = {"accepted": True, "data": {"fact": {"description": "f"}}}
    with pytest.raises(ValueError, match="complete is required"):
        validate_bootstrap_execute_payload(payload)


def test_bootstrap_execute_rejected() -> None:
    kind, data = validate_bootstrap_execute_payload({"accepted": False})
    assert kind == "rejected" and data is None


# --- bootstrap conclude ------------------------------------------------------


def test_bootstrap_conclude_fact_only() -> None:
    kind, data = validate_bootstrap_conclude_payload({"fact": {"description": "f"}})
    assert kind == "fact" and data == "f"


def test_bootstrap_conclude_unexpected_keys() -> None:
    payload = {"accepted": True, "data": {"fact": {"description": "f"}, "junk": 1}}
    with pytest.raises(ValueError, match="unexpected keys"):
        validate_bootstrap_conclude_payload(payload)


# --- explore -----------------------------------------------------------------


def test_explore_exact_description() -> None:
    kind, data = validate_explore_payload({"description": "new fact"})
    assert kind == "fact" and data == "new fact"


def test_explore_rejected() -> None:
    kind, data = validate_explore_payload({"accepted": False})
    assert kind == "rejected" and data is None


def test_explore_missing_description_raises() -> None:
    with pytest.raises(ValueError, match="accepted must be true or false"):
        validate_explore_payload({"foo": "bar"})


# --- schemas -----------------------------------------------------------------


def test_json_schemas_have_properties() -> None:
    assert "properties" in JSON_SCHEMA_CAIRN_REASON
    assert "properties" in JSON_SCHEMA_CAIRN_BOOTSTRAP
    assert JSON_SCHEMA_CAIRN_EXPLORE["properties"]["description"]["type"] == "string"
