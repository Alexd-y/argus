"""ARG-024 — ReportService canonical bundle, tier and format enums.

The ``ReportBundle`` is the immutable output of ``ReportService.generate``: a
chunk of bytes with a stable MIME type, the SHA-256 of that chunk for tamper
evidence, and an *optional* presigned URL (when the bundle was offloaded to
object storage by the caller).

Why a dedicated module?
    * ``ReportTier`` / ``ReportFormat`` enums are referenced from the API
      router, the MCP server tools, and the orchestrator — keeping them in a
      no-dependency module avoids circular imports between
      ``reports.report_service`` and ``reports.tier_classifier``.
    * The bundle carries cryptographic context (``sha256``) that downstream
      callers MUST verify before serving / signing — separating the contract
      from the orchestration logic makes that contract visible and testable.

Security guardrails
    * ``sha256`` is computed in :meth:`ReportBundle.from_content`; callers
      may NOT pass a pre-computed digest (preventing accidental mismatches
      between body and stated hash).
    * ``content`` is bytes, never ``str``. Reports that include AI-generated
      text or evidence excerpts can contain non-UTF-8 fragments after
      redaction; coercing to ``str`` would silently corrupt them.
    * ``presigned_url`` is opaque — the bundle does not validate it; the
      storage backend is responsible for issuing a URL that does not embed
      secrets in querystring.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr


class ReportTier(StrEnum):
    """Three-tier report taxonomy (Backlog/dev1_md §15)."""

    MIDGARD = "midgard"
    ASGARD = "asgard"
    VALHALLA = "valhalla"


class ReportFormat(StrEnum):
    """Canonical export formats supported by :class:`ReportService`.

    ``HTML`` / ``PDF`` / ``CSV`` / ``JSON`` are produced via the existing
    Jinja-based generators (``src.reports.generators``). ``SARIF`` and
    ``JUNIT`` are emitted by the dedicated generators in this package.
    """

    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    SARIF = "sarif"
    JUNIT = "junit"


# Canonical MIME types. Kept here (not in the router) so the bundle is the
# single source of truth — the router builds its ``Content-Type`` header
# from ``ReportBundle.mime_type`` directly.
_MIME_TYPES: dict[ReportFormat, str] = {
    ReportFormat.HTML: "text/html; charset=utf-8",
    ReportFormat.PDF: "application/pdf",
    ReportFormat.JSON: "application/json; charset=utf-8",
    ReportFormat.CSV: "text/csv; charset=utf-8",
    ReportFormat.SARIF: "application/sarif+json",
    ReportFormat.JUNIT: "application/xml; charset=utf-8",
}


# File-extension hints for storage layer ``object_key`` building. ``SARIF``
# stays ``.sarif`` (recognised by Sonar / GitHub code-scanning) rather than
# ``.json`` so consumers can distinguish at a glance.
_FILE_EXTENSIONS: dict[ReportFormat, str] = {
    ReportFormat.HTML: "html",
    ReportFormat.PDF: "pdf",
    ReportFormat.JSON: "json",
    ReportFormat.CSV: "csv",
    ReportFormat.SARIF: "sarif",
    ReportFormat.JUNIT: "xml",
}


def mime_type_for(fmt: ReportFormat) -> str:
    """Return the canonical MIME type for ``fmt``."""
    return _MIME_TYPES[fmt]


def file_extension_for(fmt: ReportFormat) -> str:
    """Return the storage-friendly file extension for ``fmt`` (no leading dot)."""
    return _FILE_EXTENSIONS[fmt]


class ReportBundle(BaseModel):
    """Immutable result of a single ReportService.generate call."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    tier: ReportTier
    format: ReportFormat
    content: bytes = Field(repr=False)
    mime_type: StrictStr = Field(min_length=1, max_length=128)
    sha256: StrictStr = Field(min_length=64, max_length=64)
    size_bytes: int = Field(ge=0)
    truncated: StrictBool = False
    presigned_url: StrictStr | None = Field(default=None, max_length=4096)

    @classmethod
    def from_content(
        cls,
        *,
        tier: ReportTier,
        fmt: ReportFormat,
        content: bytes,
        presigned_url: str | None = None,
        truncated: bool = False,
    ) -> Self:
        """Build a bundle, computing ``sha256`` and ``size_bytes`` from ``content``."""
        if not isinstance(content, (bytes, bytearray)):
            raise TypeError(
                f"ReportBundle.content must be bytes-like, got {type(content).__name__}"
            )
        body = bytes(content)
        return cls(
            tier=tier,
            format=fmt,
            content=body,
            mime_type=mime_type_for(fmt),
            sha256=hashlib.sha256(body).hexdigest(),
            size_bytes=len(body),
            truncated=truncated,
            presigned_url=presigned_url,
        )

    def file_extension(self) -> str:
        """Return the canonical file extension (no leading dot)."""
        return file_extension_for(self.format)

    def filename(self, *, stem: str = "report") -> str:
        """Build a default ``<stem>.<ext>`` filename for HTTP downloads."""
        safe_stem = "".join(
            ch if ch.isalnum() or ch in "-_." else "_" for ch in (stem or "report")
        )[:96]
        return f"{safe_stem or 'report'}.{self.file_extension()}"

    def verify_sha256(self) -> bool:
        """Recompute SHA-256 over ``content`` and compare with the stored digest."""
        return hashlib.sha256(self.content).hexdigest() == self.sha256


__all__ = [
    "ReportBundle",
    "ReportFormat",
    "ReportTier",
    "file_extension_for",
    "mime_type_for",
]
