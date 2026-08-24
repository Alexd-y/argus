"""Render all canonical report formats from one immutable snapshot (R7).

Given a :class:`ReportDocumentV1`, produce semantically-equivalent JSON / Markdown
/ XML (always) and PDF (when an ``html_to_pdf`` renderer is supplied). Each
artifact carries the metadata required by the report contract (R7.10): format,
scan_profile, snapshot_hash, generated_at, size, checksum, status.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from src.core.structured_events import (
    EVENT_REPORT_FORMAT_FAILED,
    EVENT_REPORT_FORMAT_RENDERED,
    EVENT_REPORT_SNAPSHOT_CREATED,
    emit_event,
)
from src.reports.renderers import render_html, render_json, render_markdown, render_xml
from src.reports.report_document import ReportDocumentV1

_MIME: Final[dict[str, str]] = {
    "json": "application/json",
    "md": "text/markdown",
    "xml": "application/xml",
    "pdf": "application/pdf",
    "html": "text/html",
}


@dataclass(frozen=True, slots=True)
class CanonicalArtifact:
    """One rendered canonical format + contract metadata (R7.10)."""

    format: str
    content: bytes
    mime_type: str
    scan_profile: str | None
    snapshot_hash: str
    generated_at: str
    size: int
    checksum: str  # sha256 of content
    status: str = "ready"

    def to_metadata(self) -> dict[str, object]:
        return {
            "format": self.format,
            "scan_profile": self.scan_profile,
            "snapshot_hash": self.snapshot_hash,
            "generated_at": self.generated_at,
            "size": self.size,
            "checksum": self.checksum,
            "status": self.status,
        }


def _artifact(fmt: str, content: bytes, doc: ReportDocumentV1) -> CanonicalArtifact:
    return CanonicalArtifact(
        format=fmt,
        content=content,
        mime_type=_MIME.get(fmt, "application/octet-stream"),
        scan_profile=doc.scan_profile,
        snapshot_hash=doc.snapshot_hash,
        generated_at=doc.generated_at,
        size=len(content),
        checksum=hashlib.sha256(content).hexdigest(),
    )


def render_canonical_bundle(
    doc: ReportDocumentV1,
    *,
    include_pdf: bool = False,
    html_to_pdf: Callable[[str], bytes | None] | None = None,
    scan_id: str | None = None,
    tenant_id: str | None = None,
) -> list[CanonicalArtifact]:
    """Render json/md/xml (+ optional pdf) from a single snapshot.

    All formats derive from the same ``doc``; JSON/MD/XML are deterministic so
    re-rendering an unchanged snapshot yields identical bytes (R7.9 / P7).
    """
    emit_event(
        EVENT_REPORT_SNAPSHOT_CREATED,
        tenant_id=tenant_id,
        scan_id=scan_id or doc.scan_id,
        scan_profile=doc.scan_profile,
        snapshot_hash=doc.snapshot_hash,
    )

    artifacts: list[CanonicalArtifact] = []

    text_renderers: list[tuple[str, str]] = [
        ("json", render_json(doc)),
        ("md", render_markdown(doc)),
        ("xml", render_xml(doc)),
    ]
    for fmt, text in text_renderers:
        artifacts.append(_artifact(fmt, text.encode("utf-8"), doc))
        emit_event(
            EVENT_REPORT_FORMAT_RENDERED,
            tenant_id=tenant_id,
            scan_id=scan_id or doc.scan_id,
            scan_profile=doc.scan_profile,
            report_format=fmt,
            snapshot_hash=doc.snapshot_hash,
        )

    if include_pdf:
        html = render_html(doc)
        pdf_bytes: bytes | None = None
        if html_to_pdf is not None:
            try:
                pdf_bytes = html_to_pdf(html)
            except Exception:  # noqa: BLE001 — never break bundle on PDF failure
                pdf_bytes = None
        if pdf_bytes:
            artifacts.append(_artifact("pdf", pdf_bytes, doc))
            emit_event(
                EVENT_REPORT_FORMAT_RENDERED,
                tenant_id=tenant_id,
                scan_id=scan_id or doc.scan_id,
                scan_profile=doc.scan_profile,
                report_format="pdf",
                snapshot_hash=doc.snapshot_hash,
            )
        else:
            emit_event(
                EVENT_REPORT_FORMAT_FAILED,
                tenant_id=tenant_id,
                scan_id=scan_id or doc.scan_id,
                scan_profile=doc.scan_profile,
                report_format="pdf",
                reason_code="pdf_backend_unavailable",
            )

    return artifacts


def bundle_formats(bundle: list[CanonicalArtifact]) -> set[str]:
    return {a.format for a in bundle}


__all__ = ["CanonicalArtifact", "bundle_formats", "render_canonical_bundle"]
