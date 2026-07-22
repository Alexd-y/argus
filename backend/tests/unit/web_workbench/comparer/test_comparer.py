"""Unit tests for the Comparer diff engine (WB-P3a)."""

from __future__ import annotations

import pytest

from src.web_workbench.comparer.engine import (
    ComparerError,
    DiffKind,
    DiffOp,
    compare,
    result_to_dict,
)


def test_identical_inputs_report_identical() -> None:
    payload = b"same content\nline two"
    for kind in (DiffKind.BYTE, DiffKind.WORD, DiffKind.LINE):
        result = compare(payload, payload, kind=kind)
        assert result.identical is True
        assert result.inserted == result.deleted == result.replaced == 0
        assert all(seg.op is DiffOp.EQUAL for seg in result.segments)


def test_byte_diff_detects_single_byte_change() -> None:
    result = compare(b"abc", b"abd", kind=DiffKind.BYTE)
    assert result.identical is False
    assert result.replaced >= 1


def test_word_diff_ignores_reflow_but_flags_word_change() -> None:
    left = b"the quick brown fox"
    right = b"the quick red fox"
    result = compare(left, right, kind=DiffKind.WORD)
    assert result.identical is False
    replaced = [s for s in result.segments if s.op is DiffOp.REPLACE]
    assert any("brown" in s.a and "red" in s.b for s in replaced)


def test_line_diff_reports_insertion() -> None:
    left = b"a\nb\nc"
    right = b"a\nb\nX\nc"
    result = compare(left, right, kind=DiffKind.LINE)
    assert result.inserted == 1
    assert any(s.op is DiffOp.INSERT and s.b == "X" for s in result.segments)


def test_json_diff_is_order_insensitive() -> None:
    left = b'{"a": 1, "b": 2}'
    right = b'{"b": 2, "a": 1}'
    result = compare(left, right, kind=DiffKind.JSON)
    assert result.identical is True


def test_json_diff_detects_value_change() -> None:
    result = compare(b'{"a": 1}', b'{"a": 2}', kind=DiffKind.JSON)
    assert result.identical is False
    assert result.replaced >= 1


def test_json_diff_rejects_malformed() -> None:
    with pytest.raises(ComparerError):
        compare(b"{not json}", b"{}", kind=DiffKind.JSON)


def test_dom_diff_ignores_attribute_order_and_whitespace() -> None:
    left = b'<a href="/x" class="c">Link</a>'
    right = b'<a  class="c"   href="/x">Link</a>'
    result = compare(left, right, kind=DiffKind.DOM)
    assert result.identical is True


def test_dom_diff_detects_structural_change() -> None:
    left = b"<div><span>hi</span></div>"
    right = b"<div><p>hi</p></div>"
    result = compare(left, right, kind=DiffKind.DOM)
    assert result.identical is False


def test_result_to_dict_is_json_safe() -> None:
    result = compare(b"a\nb", b"a\nc", kind=DiffKind.LINE)
    payload = result_to_dict(result)
    assert payload["kind"] == "line"
    assert isinstance(payload["segments"], list)
    assert {"op", "a", "b"} == set(payload["segments"][0])
