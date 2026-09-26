"""Phase 4 — JSON extraction from chatty agent output."""

from __future__ import annotations

import pytest
from src.cairn.output_parser import extract_json_object


def test_plain_json_object() -> None:
    assert extract_json_object('{"a": 1}') == {"a": 1}


def test_fenced_json_block() -> None:
    text = 'Here is the result:\n```json\n{"description": "found it"}\n```\nDone.'
    assert extract_json_object(text) == {"description": "found it"}


def test_json_after_prose_preamble() -> None:
    text = 'Thought: I should answer.\nFinal Answer: {"complete": {"from": ["f1"], "description": "x"}}'
    assert extract_json_object(text) == {"complete": {"from": ["f1"], "description": "x"}}


def test_json_embedded_after_invalid_brace() -> None:
    # A stray "{" that is not valid JSON, then a real object later.
    text = 'noise { not json ... then the real one: {"description": "ok"}'
    assert extract_json_object(text) == {"description": "ok"}


def test_array_only_is_not_an_object() -> None:
    with pytest.raises(ValueError, match="no JSON object found"):
        extract_json_object("[1, 2, 3]")


def test_no_json_raises() -> None:
    with pytest.raises(ValueError, match="no JSON object found"):
        extract_json_object("there is no json here")


@pytest.mark.parametrize(
    "chatter",
    [
        'prefix {"x": 1} suffix',
        'lots of words\n\n{"x": 1}\n\nmore words',
        '```\n{"x": 1}\n```',
    ],
)
def test_property_wrapped_json_is_recovered(chatter: str) -> None:
    assert extract_json_object(chatter) == {"x": 1}
