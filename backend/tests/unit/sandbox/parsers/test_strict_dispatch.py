"""Strict parser dispatch never fabricates findings on a parser gap (R9.3)."""

from __future__ import annotations

from pathlib import Path

from src.sandbox.adapter_base import ParseStrategy
from src.sandbox.parsers import (
    COVERAGE_REASON_PARSER_UNAVAILABLE,
    COVERAGE_REASON_TOOL_FAILED,
    PARSER_STATUS_FAILED,
    PARSER_STATUS_PARSED,
    PARSER_STATUS_UNPARSED,
    ParseError,
    dispatch_parse_strict,
    register_tool_parser,
    reset_registry,
)


def test_unmapped_tool_returns_unparsed_no_finding(tmp_path: Path):
    reset_registry()
    result = dispatch_parse_strict(
        ParseStrategy.JSON_OBJECT,
        b'{"some":"output"}',
        b"",
        tmp_path,
        tool_id="totally_unknown_tool",
    )
    assert result.findings == []  # no fabricated INFO finding
    assert result.parser_status == PARSER_STATUS_UNPARSED
    assert result.coverage_reason == COVERAGE_REASON_PARSER_UNAVAILABLE
    assert result.raw_available is True


def test_unknown_strategy_returns_unparsed_no_finding(tmp_path: Path):
    reset_registry()
    result = dispatch_parse_strict(
        ParseStrategy.BINARY_BLOB,
        b"",
        b"",
        tmp_path,
        tool_id="anything",
    )
    assert result.findings == []
    assert result.parser_status == PARSER_STATUS_UNPARSED
    assert result.coverage_reason == COVERAGE_REASON_PARSER_UNAVAILABLE
    assert result.raw_available is False


def test_parser_crash_returns_tool_failed_no_finding(tmp_path: Path):
    reset_registry()

    def _boom(stdout, stderr, artifacts_dir, tool_id):
        raise ParseError("kaboom")

    register_tool_parser("crashy_tool", _boom, override=True)
    result = dispatch_parse_strict(
        ParseStrategy.JSON_OBJECT,
        b"data",
        b"",
        tmp_path,
        tool_id="crashy_tool",
    )
    reset_registry()
    assert result.findings == []
    assert result.parser_status == PARSER_STATUS_FAILED
    assert result.coverage_reason == COVERAGE_REASON_TOOL_FAILED


def test_successful_parser_returns_parsed(tmp_path: Path):
    reset_registry()

    def _ok(stdout, stderr, artifacts_dir, tool_id):
        return []

    register_tool_parser("ok_tool", _ok, override=True)
    result = dispatch_parse_strict(
        ParseStrategy.JSON_OBJECT,
        b"{}",
        b"",
        tmp_path,
        tool_id="ok_tool",
    )
    reset_registry()
    assert result.parser_status == PARSER_STATUS_PARSED
    assert result.coverage_reason is None
    assert result.is_parsed is True
