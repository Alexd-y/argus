"""Tests for the declarative action interpreter with a stub HTTP client."""

from __future__ import annotations

import json

import pytest

from src.playbooks.actions import (
    ActionContext,
    ActionError,
    BrowserActionNotSupported,
    HttpRequestSpec,
    HttpResponse,
    execute_step,
    substitute,
)
from src.playbooks.schema import PlaybookStep


class _StubClient:
    """Deterministic HTTP client that records requests and returns canned responses."""

    def __init__(self, response: HttpResponse) -> None:
        self._response = response
        self.sent: list[tuple[HttpRequestSpec, str | None]] = []

    def send(self, spec: HttpRequestSpec, *, principal: str | None = None) -> HttpResponse:
        self.sent.append((spec, principal))
        return self._response


def test_http_request_builds_spec_and_saves_exchange() -> None:
    client = _StubClient(HttpResponse(status=200, body='{"id": 7}'))
    ctx = ActionContext(http=client, variables={"host": "target", "uid": "7"})
    step = PlaybookStep(
        id="probe",
        action="http_request",
        principal=None,
        save_as="resp",
        params={
            "method": "GET",
            "url": "https://{host}/users/{uid}",
            "headers": {},
        },
    )
    result = execute_step(step, ctx)
    assert result.ok
    sent_spec, principal = client.sent[0]
    assert sent_spec.url == "https://target/users/7"
    assert principal is None
    assert "resp" in ctx.variables


def test_http_request_missing_variable_fails_closed() -> None:
    client = _StubClient(HttpResponse(status=200))
    ctx = ActionContext(http=client)
    step = PlaybookStep(
        id="probe",
        action="http_request",
        params={"method": "GET", "url": "https://{unknown}/x"},
    )
    with pytest.raises(ActionError):
        execute_step(step, ctx)


def test_extract_status_code() -> None:
    client = _StubClient(HttpResponse(status=201, body='{"a": {"b": 5}}'))
    ctx = ActionContext(http=client)
    execute_step(
        PlaybookStep(
            id="probe",
            action="http_request",
            save_as="resp",
            params={"method": "GET", "url": "https://x"},
        ),
        ctx,
    )
    result = execute_step(
        PlaybookStep(
            id="get_status",
            action="extract",
            save_as="code",
            params={"from_step": "resp", "source": "status_code"},
        ),
        ctx,
    )
    assert result.value == 201
    assert ctx.variables["code"] == 201


def test_extract_json_path() -> None:
    client = _StubClient(HttpResponse(status=200, body=json.dumps({"a": {"b": 5}})))
    ctx = ActionContext(http=client)
    execute_step(
        PlaybookStep(
            id="probe",
            action="http_request",
            save_as="resp",
            params={"method": "GET", "url": "https://x"},
        ),
        ctx,
    )
    result = execute_step(
        PlaybookStep(
            id="read",
            action="extract",
            save_as="val",
            params={"from_step": "resp", "source": "response_body", "selector": "a.b"},
        ),
        ctx,
    )
    assert result.value == 5


def test_compare_equal() -> None:
    ctx = ActionContext(http=_StubClient(HttpResponse(status=200)))
    ctx.variables["x"] = "same"
    result = execute_step(
        PlaybookStep(
            id="cmp",
            action="compare",
            params={"left": "{x}", "right": "same", "mode": "equal"},
        ),
        ctx,
    )
    assert result.ok is True


def test_wait_uses_injected_sleeper() -> None:
    slept: list[float] = []
    ctx = ActionContext(http=_StubClient(HttpResponse(status=200)), sleep=slept.append)
    execute_step(
        PlaybookStep(id="w", action="wait", params={"seconds": 2.5}),
        ctx,
    )
    assert slept == [2.5]


def test_browser_action_is_not_supported_yet() -> None:
    ctx = ActionContext(http=_StubClient(HttpResponse(status=200)))
    step = PlaybookStep(
        id="click",
        action="browser_action",
        params={"kind": "click", "selector": "#submit"},
    )
    with pytest.raises(BrowserActionNotSupported):
        execute_step(step, ctx)


def test_substitute_missing_var() -> None:
    with pytest.raises(ActionError):
        substitute("{ghost}", {})
