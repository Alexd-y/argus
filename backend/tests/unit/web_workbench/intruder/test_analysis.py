"""Unit tests for Intruder response analysis (grep-match/extract, dedup)."""

from __future__ import annotations

import pytest

from src.web_workbench.intruder.analysis import (
    AnalysisError,
    dedup,
    grep_extract,
    grep_match,
)

_RESP = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nWelcome admin, id=42"


def test_grep_match_literal() -> None:
    assert grep_match(_RESP, ["admin", "guest"]) == (True, False)


def test_grep_match_regex() -> None:
    assert grep_match(_RESP, [r"id=\d+", r"token=\w+"], regex=True) == (True, False)


def test_grep_match_invalid_regex_raises() -> None:
    with pytest.raises(AnalysisError):
        grep_match(_RESP, ["("], regex=True)


def test_grep_extract_group() -> None:
    assert grep_extract(_RESP, r"id=(\d+)", group=1) == "42"


def test_grep_extract_no_match_returns_none() -> None:
    assert grep_extract(_RESP, r"token=(\w+)", group=1) is None


def test_grep_extract_out_of_range_group_raises() -> None:
    with pytest.raises(AnalysisError, match="out of range"):
        grep_extract(_RESP, r"id=(\d+)", group=5)


def test_dedup_keeps_first_per_key() -> None:
    records = [
        {"status": 200, "len": 100},
        {"status": 200, "len": 100},
        {"status": 302, "len": 0},
        {"status": 200, "len": 100},
    ]
    result = dedup(records, key=lambda r: (r["status"], r["len"]))
    assert len(result.kept) == 2
    assert result.dropped == 2
    assert result.kept[0]["status"] == 200
    assert result.kept[1]["status"] == 302
