"""Schema-validation tests for :mod:`src.playbooks.schema`."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from pydantic import ValidationError

from src.playbooks.schema import (
    ActionType,
    HttpRequestParams,
    Playbook,
    PlaybookRiskLevel,
    PlaybookStep,
    is_valid_playbook_id,
)


def test_valid_playbook_parses(playbook_dict: Callable[..., dict[str, object]]) -> None:
    playbook = Playbook(**playbook_dict())
    assert playbook.playbook_id == "idor.cross-user-read"
    assert playbook.risk_level is PlaybookRiskLevel.LOW
    assert playbook.steps[0].action is ActionType.HTTP_REQUEST


def test_extra_field_is_rejected(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    payload = playbook_dict()
    payload["unexpected_field"] = "boom"
    with pytest.raises(ValidationError):
        Playbook(**payload)


@pytest.mark.parametrize(
    "bad_id",
    [
        "IDOR.cross",  # uppercase
        "idor",  # no dot segment
        "idor.",  # trailing dot, empty segment
        "1idor.read",  # starts with digit
        "idor..read",  # empty middle segment
        "idor.read_underscore",  # underscore not allowed in segment
    ],
)
def test_invalid_playbook_id_regex(
    playbook_dict: Callable[..., dict[str, object]], bad_id: str
) -> None:
    payload = playbook_dict()
    payload["playbook_id"] = bad_id
    assert is_valid_playbook_id(bad_id) is False
    with pytest.raises(ValidationError):
        Playbook(**payload)


def test_valid_playbook_ids() -> None:
    assert is_valid_playbook_id("idor.cross-user-read")
    assert is_valid_playbook_id("auth.jwt-none")
    assert is_valid_playbook_id("a.b.c")


def test_high_risk_requires_approval(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    payload = playbook_dict(risk_level="high", requires_approval=False)
    with pytest.raises(ValidationError):
        Playbook(**payload)


def test_high_risk_with_approval_ok(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    payload = playbook_dict(risk_level="high", requires_approval=True)
    playbook = Playbook(**payload)
    assert playbook.requires_approval is True


def test_step_principal_must_be_declared(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    payload = playbook_dict()
    steps = payload["steps"]
    assert isinstance(steps, list)
    steps[0]["principal"] = "ghost"  # not in required_principals
    with pytest.raises(ValidationError):
        Playbook(**payload)


def test_duplicate_step_ids_rejected(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    payload = playbook_dict()
    steps = payload["steps"]
    assert isinstance(steps, list)
    steps[1]["id"] = steps[0]["id"]
    with pytest.raises(ValidationError):
        Playbook(**payload)


def test_http_request_params_reject_multiline_url() -> None:
    with pytest.raises(ValidationError):
        HttpRequestParams(method="GET", url="https://x/\nHost: evil")


def test_http_request_params_forbid_extra() -> None:
    with pytest.raises(ValidationError):
        HttpRequestParams(method="GET", url="https://x", shell="rm -rf /")


def test_step_params_validated_against_action() -> None:
    # http_request params missing required 'method'
    with pytest.raises(ValidationError):
        PlaybookStep(id="s1", action="http_request", params={"url": "https://x"})


def test_step_typed_params_roundtrip() -> None:
    step = PlaybookStep(
        id="wait_a_bit",
        action="wait",
        params={"seconds": 1.5},
    )
    typed = step.typed_params()
    assert getattr(typed, "seconds") == 1.5


def test_register_cleanup_reference_must_exist(
    playbook_dict: Callable[..., dict[str, object]],
) -> None:
    payload = playbook_dict()
    steps = payload["steps"]
    assert isinstance(steps, list)
    steps.append(
        {
            "id": "register_teardown",
            "action": "register_cleanup",
            "params": {"cleanup_step_id": "nonexistent"},
        }
    )
    with pytest.raises(ValidationError):
        Playbook(**payload)
