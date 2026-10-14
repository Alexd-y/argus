"""Tolerant LLM-JSON parsing + findings container normalization.

A local small GGUF model intermittently returns malformed/renamed/bare JSON.
These guard the repair passes (_parse_llm_json) and the shape normalization
(_findings_from) that keep vuln_analysis from degrading to zero findings — the
root cause of the "LLM returned invalid response for vuln_analysis" run.
"""

from __future__ import annotations

import pytest
from src.orchestration.ai_prompts import _findings_from, _parse_llm_json


class TestParseTolerant:
    def test_plain_object(self) -> None:
        assert _parse_llm_json('{"findings": [1, 2]}') == {"findings": [1, 2]}

    def test_fenced_json(self) -> None:
        assert _parse_llm_json('```json\n{"a": 1}\n```') == {"a": 1}

    def test_bare_top_level_array(self) -> None:
        assert _parse_llm_json('[{"id": 1}, {"id": 2}]') == [{"id": 1}, {"id": 2}]

    def test_trailing_commas(self) -> None:
        assert _parse_llm_json('{"findings": [1, 2,],}') == {"findings": [1, 2]}

    def test_line_comments(self) -> None:
        out = _parse_llm_json('// here you go\n{"a": 1}\n# trailing note')
        assert out == {"a": 1}

    def test_bare_python_literals(self) -> None:
        out = _parse_llm_json('{"ok": True, "bad": False, "x": None}')
        assert out == {"ok": True, "bad": False, "x": None}

    def test_single_quoted_python_literal(self) -> None:
        out = _parse_llm_json("{'findings': [{'title': 'XSS'}]}")
        assert out == {"findings": [{"title": "XSS"}]}

    def test_truncated_object_recovered(self) -> None:
        out = _parse_llm_json('{"findings": [{"title": "x"}]')
        assert out == {"findings": [{"title": "x"}]}

    def test_json_embedded_in_prose(self) -> None:
        out = _parse_llm_json('Sure! Here is the result:\n{"findings": []}\nHope that helps.')
        assert out == {"findings": []}

    def test_truncated_bare_array_salvages_complete_elements(self) -> None:
        # Model hit max_tokens mid-array → keep the two complete findings.
        out = _parse_llm_json('[{"id": 1}, {"id": 2}, {"id": 3')
        assert out == [{"id": 1}, {"id": 2}]

    def test_truncated_findings_object_salvages(self) -> None:
        out = _parse_llm_json('{"findings": [{"title": "a"}, {"title": "b')
        assert out == {"findings": [{"title": "a"}]}

    def test_truncated_mid_string_unrecoverable(self) -> None:
        # No complete element at all → nothing to salvage.
        assert _parse_llm_json('{"findings": [{"title": "abc') is None

    def test_unrecoverable_returns_none(self) -> None:
        assert _parse_llm_json("this is not json at all") is None

    def test_empty_returns_none(self) -> None:
        assert _parse_llm_json("") is None


class TestFindingsFrom:
    def test_bare_list(self) -> None:
        assert _findings_from([{"id": 1}]) == [{"id": 1}]

    @pytest.mark.parametrize("key", ["findings", "vulnerabilities", "results", "items"])
    def test_alias_keys(self, key: str) -> None:
        assert _findings_from({key: [{"id": 1}]}) == [{"id": 1}]

    def test_dict_without_findings_is_none(self) -> None:
        assert _findings_from({"summary": "nothing"}) is None

    def test_non_container_is_none(self) -> None:
        assert _findings_from("string") is None
        assert _findings_from(None) is None
        assert _findings_from(42) is None

    def test_findings_wins_over_alias_order(self) -> None:
        # "findings" is checked first.
        assert _findings_from({"findings": [1], "results": [2]}) == [1]
