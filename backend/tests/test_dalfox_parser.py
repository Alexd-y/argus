"""Dalfox stderr reflection hypotheses (XSS-PLAN-003)."""

from __future__ import annotations

from urllib.parse import unquote

from src.recon.vulnerability_analysis.parsers.dalfox_parser import (
    parse_dalfox_stderr_hypotheses,
)


def test_parse_dalfox_stderr_empty() -> None:
    assert parse_dalfox_stderr_hypotheses("", target_url="https://a.test/") == []


def test_parse_dalfox_stderr_no_reflected_keyword() -> None:
    text = "some noise\nno issues here\n"
    assert parse_dalfox_stderr_hypotheses(text, target_url="https://a.test/x?q=1") == []


def test_parse_dalfox_stderr_reflected_hypothesis() -> None:
    stderr = "[*] Reflected found in param q\n"
    rows = parse_dalfox_stderr_hypotheses(stderr, target_url="https://a.test/page?x=1")
    assert len(rows) == 1
    d = rows[0].get("data") or {}
    assert d.get("cwe") == "CWE-79"
    assert d.get("severity") == "medium"
    assert "partially_confirmed" in (d.get("description") or "")
    assert rows[0].get("source_tool") == "dalfox"


def test_parse_dalfox_stderr_parameter_line() -> None:
    stderr = "Reflected\nParameter: search\n"
    rows = parse_dalfox_stderr_hypotheses(stderr, target_url="https://b.test/")
    assert rows
    assert (rows[0].get("data") or {}).get("param") == "search"


def test_parse_dalfox_stderr_reflected_in_param_name() -> None:
    stderr = "[*] Reflected found in param world\n"
    rows = parse_dalfox_stderr_hypotheses(
        stderr,
        target_url="https://alf.nu/alert1?world=1&level=alert0",
    )
    assert len(rows) == 1
    assert (rows[0].get("data") or {}).get("param") == "world"
    assert (rows[0].get("data") or {}).get("url", "").startswith("https://")


def test_parse_dalfox_stderr_reflected_named_param_per_line() -> None:
    stderr = (
        "[I] Reflected level param =>\n"
        "[I] Reflected world param =>\n"
    )
    target = "https://alf.nu/alert1?world=1&level=alert0"
    rows = parse_dalfox_stderr_hypotheses(stderr, target_url=target)
    assert len(rows) == 2
    params = [(r.get("data") or {}).get("param") for r in rows]
    assert set(params) == {"level", "world"}
    for r in rows:
        d = r.get("data") or {}
        assert d.get("cwe") == "CWE-79"
        assert d.get("severity") == "high"
        assert d.get("cvss_score") == 7.2
        poc_curl = d.get("poc_curl") or ""
        assert "alert(1)" in unquote(poc_curl)
