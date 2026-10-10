"""Phase 5 — logical report-format -> file-extension resolver (RC-19).

A raw logical format (``canonical_json``, ``valhalla_llm_xml``, …) must never become a
file extension: MinIO objects and Content-Disposition names must carry a real
extension (``.json``, ``.xml``, ``.zip``) while the logical name stays the DB/API key.
"""

from __future__ import annotations

import pytest
from src.reports.report_bundle import extension_for_logical_format, mime_for_logical_format
from src.storage.s3 import build_report_object_key


@pytest.mark.parametrize(
    ("fmt", "ext"),
    [
        ("pdf", "pdf"),
        ("html", "html"),
        ("json", "json"),
        ("md", "md"),
        ("xml", "xml"),
        ("csv", "csv"),
        ("canonical_json", "json"),
        ("canonical_md", "md"),
        ("canonical_xml", "xml"),
        ("canonical_html", "html"),
        ("canonical_pdf", "pdf"),
        ("valhalla_llm_json", "json"),
        ("valhalla_llm_md", "md"),
        ("valhalla_llm_xml", "xml"),
        ("valhalla_llm_html", "html"),
        ("valhalla_llm_pdf", "pdf"),
        ("valhalla_llm_manifest", "json"),
        ("valhalla_verification_kit", "zip"),
        ("export_validation_report", "json"),
        ("technologies_csv", "csv"),
        ("outdated_components_csv", "csv"),
        ("tool_health_csv", "csv"),
        ("valhalla_sections.csv", "csv"),
    ],
)
def test_extension_for_logical_format(fmt, ext):
    assert extension_for_logical_format(fmt) == ext


def test_extension_unknown_falls_back_safely():
    # An unknown logical name never leaks back as the raw string extension.
    assert extension_for_logical_format("weird_internal_blob") == "bin"


def test_mime_for_logical_format():
    assert mime_for_logical_format("canonical_json") == "application/json"
    assert mime_for_logical_format("valhalla_verification_kit") == "application/zip"


def test_build_report_object_key_uses_real_extension():
    key = build_report_object_key("ten", "scan", "valhalla", "rep", "canonical_json")
    assert key.endswith("rep.json")
    assert ".canonical_json" not in key
    key_kit = build_report_object_key("ten", "scan", "valhalla", "rep", "valhalla_verification_kit")
    assert key_kit.endswith("rep.zip")
