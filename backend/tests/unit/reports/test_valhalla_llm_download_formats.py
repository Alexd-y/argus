"""VH-LLM-09: Valhalla LLM artifact formats are downloadable via the reports API."""

from src.api.routers.reports import CONTENT_TYPES, VALID_FORMATS

_EXPECTED = {
    "valhalla_llm_json",
    "valhalla_llm_md",
    "valhalla_llm_xml",
    "valhalla_llm_html",
    "valhalla_llm_pdf",
    "valhalla_llm_manifest",
}


def test_valhalla_llm_formats_are_valid_download_formats():
    assert _EXPECTED <= VALID_FORMATS


def test_every_valid_format_has_a_content_type():
    # The download endpoint indexes CONTENT_TYPES[fmt] directly, so every
    # accepted format must have a media type or streaming would KeyError.
    assert set(CONTENT_TYPES) >= VALID_FORMATS


def test_valhalla_llm_xml_content_type_is_xml():
    assert CONTENT_TYPES["valhalla_llm_xml"].startswith("application/xml")
    assert CONTENT_TYPES["valhalla_llm_manifest"].startswith("application/json")
