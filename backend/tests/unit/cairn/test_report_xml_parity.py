"""Phase 16 — structured XML report projection (VP-10) well-formedness + escaping."""

from __future__ import annotations

from xml.dom.minidom import parseString  # noqa: S408 - parsing our OWN generated trusted output

from src.reports.generators import _REPORT_XML_NS, _value_to_xml, _xml_escape, _xml_tag


def test_xml_escape_handles_specials() -> None:
    assert _xml_escape('a & b < c > d "e"') == "a &amp; b &lt; c &gt; d &quot;e&quot;"


def test_xml_tag_sanitizes_keys() -> None:
    assert _xml_tag("owasp category") == "owasp_category"
    assert _xml_tag("123bad")[0] == "_"


def test_value_to_xml_nested_is_wellformed() -> None:
    payload = {
        "metadata": {"report_id": "r1", "target": "http://t & x"},
        "findings": [{"title": "XSS <script>"}, {"title": "SQLi"}],
        "empty": None,
        "flag": True,
    }
    body = "".join(_value_to_xml(str(k), v) for k, v in payload.items())
    doc = f'<?xml version="1.0" encoding="UTF-8"?><report xmlns="{_REPORT_XML_NS}">{body}</report>'
    parsed = parseString(doc)  # raises if not well-formed
    root = parsed.documentElement
    assert root.tagName == "report"
    assert root.getAttribute("xmlns") == _REPORT_XML_NS
    # escaped content survived and re-parsed to the original text
    findings = root.getElementsByTagName("findings")[0]
    titles = [n.firstChild.data for n in findings.getElementsByTagName("title")]
    assert "XSS <script>" in titles
    assert "SQLi" in titles


def test_value_to_xml_list_uses_item_elements() -> None:
    xml = _value_to_xml("ports", [80, 443])
    assert xml == "<ports><item>80</item><item>443</item></ports>"
