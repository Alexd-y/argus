"""Unit tests for the interception rule engine (WB-P2a)."""

from __future__ import annotations

from src.web_workbench.proxy.intercept_rules import (
    InterceptAction,
    InterceptRule,
    InterceptRuleSet,
)
from src.web_workbench.proxy.transport import NormalizedRequest


def _req(raw: bytes) -> NormalizedRequest:
    return NormalizedRequest.parse(raw)


GET_API = _req(b"GET /api/users HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
POST_JSON = _req(
    b"POST /submit HTTP/1.1\r\nHost: app.example.com\r\n" b"Content-Type: application/json\r\n\r\n"
)


def test_empty_rule_set_uses_default() -> None:
    rs = InterceptRuleSet(default_action=InterceptAction.PASS)
    assert rs.decide(GET_API) is InterceptAction.PASS


def test_first_match_wins() -> None:
    rs = InterceptRuleSet(
        rules=(
            InterceptRule(action=InterceptAction.DROP, path_prefix="/api"),
            InterceptRule(action=InterceptAction.INTERCEPT, path_prefix="/api"),
        ),
    )
    assert rs.decide(GET_API) is InterceptAction.DROP


def test_method_match() -> None:
    rs = InterceptRuleSet(
        rules=(InterceptRule(action=InterceptAction.INTERCEPT, methods=frozenset({"post"})),)
    )
    assert rs.decide(POST_JSON) is InterceptAction.INTERCEPT
    assert rs.decide(GET_API) is InterceptAction.PASS


def test_host_suffix_match_case_insensitive() -> None:
    rs = InterceptRuleSet(
        rules=(InterceptRule(action=InterceptAction.INTERCEPT, host_suffix="EXAMPLE.com"),)
    )
    assert rs.decide(GET_API) is InterceptAction.INTERCEPT


def test_content_type_contains() -> None:
    rs = InterceptRuleSet(
        rules=(InterceptRule(action=InterceptAction.INTERCEPT, content_type_contains="json"),)
    )
    assert rs.decide(POST_JSON) is InterceptAction.INTERCEPT
    assert rs.decide(GET_API) is InterceptAction.PASS


def test_path_prefix_absolute_form() -> None:
    req = _req(b"GET https://app.example.com/admin/x HTTP/1.1\r\nHost: app.example.com\r\n\r\n")
    rs = InterceptRuleSet(rules=(InterceptRule(action=InterceptAction.DROP, path_prefix="/admin"),))
    assert rs.decide(req) is InterceptAction.DROP


def test_no_match_falls_through_to_default_drop() -> None:
    rs = InterceptRuleSet(
        rules=(InterceptRule(action=InterceptAction.INTERCEPT, host_suffix="other.tld"),),
        default_action=InterceptAction.DROP,
    )
    assert rs.decide(GET_API) is InterceptAction.DROP
