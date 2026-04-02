"""Tests for the LLM-based deduplication module (ENH-V3)."""

import pytest

from src.dedup.llm_dedup import (
    DedupResult,
    _build_existing_xml,
    _extract_xml_tag,
    _parse_dedupe_response,
)


class TestExtractXmlTag:
    def test_extracts_simple_tag(self):
        text = "<is_duplicate>true</is_duplicate>"
        assert _extract_xml_tag(text, "is_duplicate") == "true"

    def test_extracts_with_whitespace(self):
        text = "<confidence>  0.85  </confidence>"
        assert _extract_xml_tag(text, "confidence") == "0.85"

    def test_returns_empty_on_missing(self):
        text = "<other>value</other>"
        assert _extract_xml_tag(text, "missing") == ""

    def test_case_insensitive(self):
        text = "<Is_Duplicate>false</Is_Duplicate>"
        assert _extract_xml_tag(text, "is_duplicate") == "false"


class TestParseDedupResponse:
    def test_parse_duplicate(self):
        xml = """<dedupe_result>
  <is_duplicate>true</is_duplicate>
  <duplicate_id>finding-123</duplicate_id>
  <confidence>0.92</confidence>
  <reason>Same SQLi in /login endpoint, same parameter 'username'</reason>
</dedupe_result>"""
        result = _parse_dedupe_response(xml)
        assert result.is_duplicate is True
        assert result.duplicate_id == "finding-123"
        assert result.confidence == 0.92
        assert "SQLi" in result.reason

    def test_parse_not_duplicate(self):
        xml = """<dedupe_result>
  <is_duplicate>false</is_duplicate>
  <duplicate_id></duplicate_id>
  <confidence>0.95</confidence>
  <reason>Different endpoints: /login vs /search</reason>
</dedupe_result>"""
        result = _parse_dedupe_response(xml)
        assert result.is_duplicate is False
        assert result.duplicate_id is None
        assert result.confidence == 0.95

    def test_parse_invalid_xml_returns_safe_default(self):
        result = _parse_dedupe_response("not xml at all")
        assert result.is_duplicate is False
        assert result.confidence == 0.0

    def test_confidence_clamped(self):
        xml = "<dedupe_result><is_duplicate>true</is_duplicate><confidence>1.5</confidence><reason>test</reason></dedupe_result>"
        result = _parse_dedupe_response(xml)
        assert result.confidence == 1.0

    def test_negative_confidence_clamped(self):
        xml = "<dedupe_result><is_duplicate>false</is_duplicate><confidence>-0.5</confidence><reason>test</reason></dedupe_result>"
        result = _parse_dedupe_response(xml)
        assert result.confidence == 0.0


class TestBuildExistingXml:
    def test_formats_findings(self):
        findings = [
            {"id": "f1", "title": "SQLi in login", "cwe": "CWE-89", "owasp_category": "A03", "url": "/login", "description": "SQL injection"},
            {"id": "f2", "title": "XSS in search", "cwe": "CWE-79", "owasp_category": "A07", "url": "/search", "description": "Reflected XSS"},
        ]
        xml = _build_existing_xml(findings)
        assert '<report id="f1">' in xml
        assert '<report id="f2">' in xml
        assert "SQLi in login" in xml
        assert "XSS in search" in xml

    def test_limits_to_20_findings(self):
        findings = [{"id": f"f{i}", "title": f"Finding {i}", "description": "desc"} for i in range(30)]
        xml = _build_existing_xml(findings)
        assert '<report id="f10">' in xml
        assert '<report id="f29">' in xml

    def test_empty_list(self):
        xml = _build_existing_xml([])
        assert xml == ""


class TestDedupResult:
    def test_frozen_dataclass(self):
        r = DedupResult(is_duplicate=True, confidence=0.9, duplicate_id="f1", reason="same vuln")
        assert r.is_duplicate is True
        assert r.confidence == 0.9
        assert r.duplicate_id == "f1"
        assert r.reason == "same vuln"
