"""Wave 5 / R-9.7 (stage B) — structured-output parse-quality metric.

The first model-quality metric measurable immediately: how often an LLM response
parsed cleanly on the first try (``direct``) vs only via json_extract's fallback
heuristics vs not at all. This is the baseline schema enforcement (stage V /
R-9.9) must move, so it must be wired to the real extractor.
"""

from __future__ import annotations

import pytest
from src.eval.rates import (
    record_json_parse,
    reset_structured_parse_rates,
    snapshot_structured_parse_rates,
)
from src.llm.json_extract import extract_json_object


@pytest.fixture(autouse=True)
def _reset():
    reset_structured_parse_rates()
    yield
    reset_structured_parse_rates()


def test_record_and_snapshot_rates():
    record_json_parse(tier="direct")
    record_json_parse(tier="direct")
    record_json_parse(tier="fence")
    record_json_parse(tier="balanced")
    record_json_parse(tier="failed")
    snap = snapshot_structured_parse_rates()
    assert snap.total == 5
    assert snap.direct_parse_rate == 2 / 5
    assert snap.fallback_parse_rate == 2 / 5  # fence + balanced
    assert snap.parse_failure_rate == 1 / 5


def test_empty_snapshot_is_zero():
    snap = snapshot_structured_parse_rates()
    assert snap.total == 0
    assert snap.direct_parse_rate == 0.0


def test_extractor_records_direct_for_clean_json():
    assert extract_json_object('{"a": 1}') == {"a": 1}
    snap = snapshot_structured_parse_rates()
    assert (snap.total, snap.direct_parse_rate) == (1, 1.0)


def test_extractor_records_fallback_for_fenced_and_prose():
    assert extract_json_object('```json\n{"a": 1}\n```') == {"a": 1}  # fence
    assert extract_json_object('Thought: here it is {"b": 2} trailing prose') == {
        "b": 2
    }  # balanced
    snap = snapshot_structured_parse_rates()
    assert snap.total == 2
    assert snap.fallback_parse_rate == 1.0
    assert snap.direct_parse_rate == 0.0


def test_extractor_records_failure_for_garbage():
    assert extract_json_object("not json at all") is None
    snap = snapshot_structured_parse_rates()
    assert snap.total == 1
    assert snap.parse_failure_rate == 1.0


def test_empty_input_is_not_counted():
    assert extract_json_object("") is None
    assert extract_json_object("   ") is None
    # empty input is not a model parse attempt → not recorded
    assert snapshot_structured_parse_rates().total == 0
