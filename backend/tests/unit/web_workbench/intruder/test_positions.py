"""Unit tests for Intruder insertion-point parsing + byte-exact rendering."""

from __future__ import annotations

import pytest

from src.web_workbench.intruder.positions import (
    MAX_POSITIONS,
    IntruderError,
    parse_template,
)


def test_parse_no_positions_round_trips() -> None:
    raw = b"GET /health HTTP/1.1\r\nHost: app\r\n\r\n"
    parsed = parse_template(raw)
    assert parsed.position_count == 0
    assert parsed.render_base() == raw


def test_parse_extracts_base_values_and_round_trips() -> None:
    raw = b"POST /login HTTP/1.1\r\nHost: app\r\n\r\nuser={{admin}}&pass={{secret}}"
    parsed = parse_template(raw)
    assert parsed.position_count == 2
    assert parsed.base_values == (b"admin", b"secret")
    # Byte-exact reconstruction with the original base values.
    assert (
        parsed.render_base() == b"POST /login HTTP/1.1\r\nHost: app\r\n\r\nuser=admin&pass=secret"
    )


def test_render_injects_values_byte_exact() -> None:
    parsed = parse_template(b"a={{x}}&b={{y}}")
    assert parsed.render([b"1", b"2"]) == b"a=1&b=2"


def test_render_wrong_arity_raises() -> None:
    parsed = parse_template(b"a={{x}}")
    with pytest.raises(IntruderError):
        parsed.render([b"1", b"2"])


def test_unbalanced_marker_raises() -> None:
    with pytest.raises(IntruderError, match="unbalanced"):
        parse_template(b"a={{x")


def test_empty_base_value_is_allowed() -> None:
    parsed = parse_template(b"a={{}}")
    assert parsed.base_values == (b"",)
    assert parsed.render([b"payload"]) == b"a=payload"


def test_custom_markers() -> None:
    parsed = parse_template(b"a=<FUZZ>", open_marker=b"<", close_marker=b">")
    assert parsed.base_values == (b"FUZZ",)
    assert parsed.render([b"z"]) == b"a=z"


def test_too_many_positions_raises() -> None:
    raw = b"".join(b"{{x}}" for _ in range(MAX_POSITIONS + 1))
    with pytest.raises(IntruderError, match="too many"):
        parse_template(raw)
