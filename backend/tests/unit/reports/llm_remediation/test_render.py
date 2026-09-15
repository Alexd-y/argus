"""VH-LLM-08: 4-format rendering, semantic parity, XML XSD validation."""

from src.reports.llm_remediation.document import ValhallaFindingNode, ValhallaLlmDocument
from src.reports.llm_remediation.render import (
    assert_semantic_parity,
    parity_facts,
    render_all_text_formats,
    render_html,
    render_markdown,
    render_xml,
    validate_valhalla_xml,
)


def test_all_formats_contain_mandatory_blocks(complete_document):
    md = render_markdown(complete_document)
    html = render_html(complete_document)
    xml = render_xml(complete_document)

    for text in (md, html):
        assert "LLM-план устранения" in text
        assert "LLM-вывод по закрытию" in text
        assert "Итоговые выводы по устранению и закрытию" in text
    # XML uses typed elements, not prose headings.
    assert "<remediation-analysis" in xml
    assert "<closure-conclusion" in xml
    assert 'status="fixed_verified"' in xml


def test_semantic_parity_holds_across_formats(complete_document):
    rendered = render_all_text_formats(complete_document)
    missing = assert_semantic_parity(complete_document, rendered)
    assert missing == {}, f"parity gaps: {missing}"
    # Sanity: parity facts are non-trivial.
    facts = parity_facts(complete_document)
    assert "F-1" in facts and "fixed_verified" in facts and "C1" in facts


def test_xml_is_schema_valid(complete_document):
    xml = render_xml(complete_document)
    errors = validate_valhalla_xml(xml)
    assert errors == [], f"xml validation errors: {errors}"


def test_xml_rejects_external_entities():
    malicious = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
        '<valhalla-llm-report version="1.0" doc_version="v1" content_hash="x" '
        'assessment_completeness="complete">&xxe;</valhalla-llm-report>'
    )
    errors = validate_valhalla_xml(malicious)
    assert errors
    assert any("parse_error" in e or "entit" in e.lower() for e in errors)


def test_xml_missing_required_structure_is_flagged():
    errors = validate_valhalla_xml('<wrong-root version="1.0"></wrong-root>')
    assert any("unexpected_root" in e for e in errors)
    assert any("missing_child" in e for e in errors)


def test_html_escapes_payload_as_text():
    # A finding whose title contains markup must be escaped, not executed.
    doc = ValhallaLlmDocument(
        report_id="R1",
        findings=[ValhallaFindingNode(finding_id="F-x", title="<script>alert(1)</script>")],
    ).finalized()
    html = render_html(doc)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
