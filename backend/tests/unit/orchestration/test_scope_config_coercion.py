"""run_reporting scope_config coercion — string RoE context must not break reporting."""

from __future__ import annotations

from src.orchestration.handlers import _coerce_scope_config


def test_string_wrapped_under_rules_of_engagement():
    out = _coerce_scope_config("Max requests/second: 10\nExploitation phase: enabled")
    assert out == {"rules_of_engagement": "Max requests/second: 10\nExploitation phase: enabled"}


def test_dict_passthrough():
    d = {"focus": ["/api"], "max_rps": 10}
    assert _coerce_scope_config(d) is d


def test_none_and_empty_string_become_none():
    assert _coerce_scope_config(None) is None
    assert _coerce_scope_config("   ") is None
    assert _coerce_scope_config("") is None


def test_other_types_dropped():
    assert _coerce_scope_config(123) is None
    assert _coerce_scope_config(["a"]) is None
