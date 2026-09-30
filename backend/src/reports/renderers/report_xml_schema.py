"""Valhalla report XML: XSD validation + safe parsing (formats prompt Phase 4).

* :func:`validate_valhalla_report_xml` validates a rendered canonical XML document
  against the versioned XSD file ``backend/config/schemas/valhalla_report_v2.xsd``.
* :func:`safe_parse_xml` parses with external entities and DTDs disabled (no XXE).

lxml is used for XSD validation (schema-aware); defusedxml guards the parse path.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

#: Path to the versioned XSD (single source of truth; not an inline string).
XSD_PATH: Path = (
    Path(__file__).resolve().parents[3] / "config" / "schemas" / "valhalla_report_v2.xsd"
)


class XmlSecurityError(RuntimeError):
    """Raised when an XML document contains a DTD or external/general entity (XXE)."""


@lru_cache(maxsize=1)
def _load_schema():
    from lxml import etree  # noqa: PLC0415 — optional heavy dep, imported on demand

    with XSD_PATH.open("rb") as fh:
        schema_doc = etree.parse(fh)  # noqa: S320 — trusted, repo-local schema file
    return etree.XMLSchema(schema_doc)


def _safe_lxml_parser():
    from lxml import etree  # noqa: PLC0415

    # resolve_entities=False + no_network + no DTD load → no XXE / entity expansion.
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
    )


def validate_valhalla_report_xml(xml_text: str) -> list[str]:
    """Return XSD validation errors for ``xml_text`` (empty list == valid)."""
    from lxml import etree  # noqa: PLC0415

    try:
        doc = etree.fromstring(xml_text.encode("utf-8"), parser=_safe_lxml_parser())
    except etree.XMLSyntaxError as exc:
        return [f"xml_syntax_error: {exc}"]
    schema = _load_schema()
    if schema.validate(doc):
        return []
    return [f"{e.line}:{e.column}: {e.message}" for e in schema.error_log]


def safe_parse_xml(xml_text: str):
    """Parse ``xml_text`` rejecting DTDs and external/general entities (XXE-safe).

    Raises :class:`XmlSecurityError` when a DTD or entity is present.
    """
    from defusedxml.common import DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden
    from defusedxml.ElementTree import fromstring as _defused_fromstring  # noqa: PLC0415

    try:
        return _defused_fromstring(xml_text)
    except (DTDForbidden, EntitiesForbidden, ExternalReferenceForbidden) as exc:
        raise XmlSecurityError(str(exc)) from exc


__all__ = [
    "XSD_PATH",
    "XmlSecurityError",
    "safe_parse_xml",
    "validate_valhalla_report_xml",
]
