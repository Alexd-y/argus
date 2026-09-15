"""Atomic multi-format release + manifest for the Valhalla LLM deliverable (VH-LLM-09).

All requested artifacts (MD/XML/HTML/JSON, optionally PDF) are rendered from the
single :class:`ValhallaLlmDocument` and validated *before* the release is marked
``ready``. A failure of any one format, an invalid XML, a parity gap or an
incomplete mandatory LLM analysis blocks the whole release — it is never masked
by the other formats being ready (prompt §12). Distinct status fields are kept
separate (generation / llm-analysis / assessment / review / integrity) per §12.

The manifest records the snapshot content hash plus a per-artifact SHA-256. A
plain content hash is NOT a signature and is documented as such.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from src.reports.llm_remediation.document import AssessmentCompleteness, ValhallaLlmDocument
from src.reports.llm_remediation.pdf import PDF_AVAILABLE, render_pdf
from src.reports.llm_remediation.render import (
    assert_semantic_parity,
    render_all_text_formats,
    validate_valhalla_xml,
)

#: Formats a Valhalla LLM release may contain. Unknown formats are rejected
#: (prompt §12: "неизвестный формат даёт ошибку, а не default/CSV/JUnit").
VALHALLA_LLM_FORMATS: frozenset[str] = frozenset({"json", "md", "xml", "html", "pdf"})

_MIME: dict[str, str] = {
    "json": "application/json; charset=utf-8",
    "md": "text/markdown; charset=utf-8",
    "xml": "application/xml; charset=utf-8",
    "html": "text/html; charset=utf-8",
    "pdf": "application/pdf",
}


class GenerationStatus(StrEnum):
    READY = "ready"
    DRAFT = "draft"
    FAILED = "failed"


class UnknownFormatError(ValueError):
    """Raised when a requested format is not a valid Valhalla LLM format."""


@dataclass(frozen=True)
class ValhallaArtifact:
    format: str
    content: bytes
    mime_type: str
    sha256: str
    size_bytes: int

    @classmethod
    def build(cls, fmt: str, content: bytes) -> ValhallaArtifact:
        return cls(
            format=fmt,
            content=content,
            mime_type=_MIME[fmt],
            sha256=hashlib.sha256(content).hexdigest(),
            size_bytes=len(content),
        )


class ValhallaReleaseManifest(BaseModel):
    """Release manifest — identity, hashes and separated status fields."""

    model_config = ConfigDict(extra="forbid")

    report_version: str
    canonical_snapshot_hash: str = ""
    content_hash: str
    formats: list[str] = Field(default_factory=list)
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    generation_status: GenerationStatus = GenerationStatus.FAILED
    assessment_completeness: AssessmentCompleteness = AssessmentCompleteness.INCOMPLETE
    review_status: str = "pending"
    xml_valid: bool = False
    parity_ok: bool = False
    errors: list[str] = Field(default_factory=list)
    # A content hash is integrity, not authenticity — documented, not a signature.
    hash_is_signature: bool = False


@dataclass
class ValhallaRelease:
    manifest: ValhallaReleaseManifest
    artifacts: dict[str, ValhallaArtifact] = field(default_factory=dict)

    @property
    def is_ready(self) -> bool:
        return self.manifest.generation_status == GenerationStatus.READY


def _normalize_formats(formats: list[str] | None) -> list[str]:
    requested = [f.lower().strip() for f in (formats or ["json", "md", "xml", "html"])]
    unknown = [f for f in requested if f not in VALHALLA_LLM_FORMATS]
    if unknown:
        raise UnknownFormatError(f"unknown Valhalla LLM format(s): {unknown}")
    # Preserve order, drop dupes.
    return list(dict.fromkeys(requested))


def build_valhalla_release(
    doc: ValhallaLlmDocument,
    *,
    formats: list[str] | None = None,
    allow_incomplete_draft: bool = False,
) -> ValhallaRelease:
    """Render + validate all requested formats atomically.

    ``ready`` is granted only when: the mandatory LLM analysis is complete (or a
    draft is explicitly allowed), every requested format rendered, the XML is
    schema-valid and all formats reach semantic parity. Any failure yields
    ``failed`` (or ``draft``) with recorded errors and no ``ready`` masking.
    """

    requested = _normalize_formats(formats)
    errors: list[str] = []

    text_formats = render_all_text_formats(doc)  # json/md/xml/html

    # XML schema validity.
    xml_errors = validate_valhalla_xml(text_formats["xml"])
    xml_valid = not xml_errors
    if xml_errors:
        errors.extend(f"xml:{e}" for e in xml_errors)

    # Semantic parity across the textual formats.
    parity_gaps = assert_semantic_parity(doc, text_formats)
    parity_ok = not parity_gaps
    if parity_gaps:
        for fmt, gaps in parity_gaps.items():
            errors.append(f"parity:{fmt}:missing:{','.join(gaps)}")

    artifacts: dict[str, ValhallaArtifact] = {}
    for fmt in requested:
        if fmt in text_formats:
            artifacts[fmt] = ValhallaArtifact.build(fmt, text_formats[fmt].encode("utf-8"))
        elif fmt == "pdf":
            if not PDF_AVAILABLE:
                errors.append("pdf:renderer_unavailable")
                continue
            try:
                artifacts[fmt] = ValhallaArtifact.build(fmt, render_pdf(doc))
            except Exception as exc:  # a single format failure must not be masked
                errors.append(f"pdf:render_failed:{exc}")

    built_all = all(fmt in artifacts for fmt in requested)
    if not built_all:
        missing = [fmt for fmt in requested if fmt not in artifacts]
        errors.append(f"formats:not_built:{','.join(missing)}")

    completeness = doc.assessment_completeness
    llm_complete = completeness == AssessmentCompleteness.COMPLETE

    if llm_complete and built_all and xml_valid and parity_ok:
        generation_status = GenerationStatus.READY
    elif allow_incomplete_draft and built_all and xml_valid and parity_ok:
        generation_status = GenerationStatus.DRAFT
    else:
        generation_status = GenerationStatus.FAILED

    manifest = ValhallaReleaseManifest(
        report_version=doc.report_version,
        canonical_snapshot_hash=doc.canonical_snapshot_hash,
        content_hash=doc.content_hash,
        formats=requested,
        artifact_hashes={fmt: art.sha256 for fmt, art in artifacts.items()},
        generation_status=generation_status,
        assessment_completeness=completeness,
        xml_valid=xml_valid,
        parity_ok=parity_ok,
        errors=errors,
    )
    return ValhallaRelease(manifest=manifest, artifacts=artifacts)


__all__ = [
    "VALHALLA_LLM_FORMATS",
    "GenerationStatus",
    "UnknownFormatError",
    "ValhallaArtifact",
    "ValhallaRelease",
    "ValhallaReleaseManifest",
    "build_valhalla_release",
]
