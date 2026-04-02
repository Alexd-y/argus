"""VHQ-003 — Finding quality filter before report generation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from src.reports.finding_quality_filter import (
    _MIN_DESCRIPTION_LENGTH,
    _get_attr,
    _is_valid_description,
    _is_valid_title,
    filter_valid_findings,
)


def _valid_dict() -> dict[str, Any]:
    return {
        "title": "Reflected XSS in search",
        "description": "User input is echoed without encoding in the results page.",
    }


def test_filter_valid_findings_empty_list_returns_empty_list() -> None:
    findings: list[Any] = []
    out = filter_valid_findings(findings)
    assert out == []
    assert out is findings


def test_filter_valid_findings_valid_finding_passes_through() -> None:
    f = _valid_dict()
    out = filter_valid_findings([f])
    assert len(out) == 1
    assert out[0] is f


def test_filter_valid_findings_unknown_finding_title_removed() -> None:
    bad = {**_valid_dict(), "title": "unknown finding"}
    out = filter_valid_findings([bad])
    assert out == []


def test_filter_valid_findings_unknown_title_case_insensitive_removed() -> None:
    bad = {**_valid_dict(), "title": "Unknown"}
    out = filter_valid_findings([bad])
    assert out == []


def test_filter_valid_findings_empty_title_removed() -> None:
    bad = {**_valid_dict(), "title": ""}
    out = filter_valid_findings([bad])
    assert out == []


def test_filter_valid_findings_whitespace_only_title_removed() -> None:
    bad = {**_valid_dict(), "title": "   \t\n  "}
    out = filter_valid_findings([bad])
    assert out == []


def test_filter_valid_findings_none_title_removed() -> None:
    bad = {**_valid_dict(), "title": None}
    out = filter_valid_findings([bad])
    assert out == []


def test_filter_valid_findings_short_description_removed() -> None:
    short = "x" * (_MIN_DESCRIPTION_LENGTH - 1)
    bad = {**_valid_dict(), "description": short}
    out = filter_valid_findings([bad])
    assert out == []


def test_filter_valid_findings_empty_description_removed() -> None:
    bad = {**_valid_dict(), "description": ""}
    out = filter_valid_findings([bad])
    assert out == []


def test_filter_valid_findings_whitespace_only_description_removed() -> None:
    bad = {**_valid_dict(), "description": "   \n\t  "}
    out = filter_valid_findings([bad])
    assert out == []


def test_filter_valid_findings_mix_returns_only_valid() -> None:
    good = _valid_dict()
    bad_title = {**_valid_dict(), "title": "placeholder"}
    bad_desc = {**_valid_dict(), "description": "too short"}
    out = filter_valid_findings([bad_title, good, bad_desc])
    assert len(out) == 1
    assert out[0] is good


def test_filter_valid_findings_dict_style() -> None:
    d = _valid_dict()
    out = filter_valid_findings([d])
    assert out == [d]


@dataclass
class _ObjectFinding:
    title: str | None
    description: str | None = None


def test_filter_valid_findings_object_style() -> None:
    o = _ObjectFinding(
        title="IDOR on account API",
        description="Sequential IDs allow accessing other users' data via /api/user/{id}.",
    )
    out = filter_valid_findings([o])
    assert len(out) == 1
    assert out[0] is o


def test_filter_valid_findings_object_style_invalid_filtered() -> None:
    thin = _ObjectFinding(title="untitled", description="Enough text here for minimum length.")
    out = filter_valid_findings([thin])
    assert out == []


def test_get_attr_dict_and_object() -> None:
    d: dict[str, Any] = {"title": "from dict", "description": "x" * _MIN_DESCRIPTION_LENGTH}
    o = _ObjectFinding(title="from object", description="y" * _MIN_DESCRIPTION_LENGTH)
    assert _get_attr(d, "title") == "from dict"
    assert _get_attr(d, "missing") is None
    assert _get_attr(o, "title") == "from object"
    assert _get_attr(o, "nope") is None


@pytest.mark.parametrize(
    ("title", "expected"),
    [
        ("Real finding title", True),
        ("unknown finding", False),
        ("UNKNOWN", False),
        ("", False),
        ("   ", False),
        (None, False),
        (123, False),
    ],
)
def test_is_valid_title(title: Any, expected: bool) -> None:
    assert _is_valid_title(title) is expected


@pytest.mark.parametrize(
    ("description", "expected"),
    [
        ("Exactly ten.", True),
        ("x" * _MIN_DESCRIPTION_LENGTH, True),
        ("short", False),
        ("", False),
        ("  \t  ", False),
        (None, False),
        (["not", "a", "string"], False),
    ],
)
def test_is_valid_description(description: Any, expected: bool) -> None:
    assert _is_valid_description(description) is expected
