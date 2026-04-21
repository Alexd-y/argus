"""Schemas for MCP ``report.*`` tools (Backlog/dev1_md §13)."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictStr


class ReportTier(StrEnum):
    """Closed taxonomy of report tiers exposed via MCP.

    Mirrors the ARGUS Midgard / Asgard / Valhalla cascade. Tier selection
    is gated by the tenant plan inside :class:`PolicyEngine`; the MCP layer
    only echoes the requested tier and reports the policy decision.
    """

    MIDGARD = "midgard"
    ASGARD = "asgard"
    VALHALLA = "valhalla"


class ReportFormat(StrEnum):
    """Closed taxonomy of report output formats.

    The MCP server intentionally does NOT expose ``valhalla_sections_csv``
    (a debug helper) — only the canonical formats listed here.
    """

    HTML = "html"
    PDF = "pdf"
    JSON = "json"
    CSV = "csv"
    SARIF = "sarif"
    JUNIT = "junit"


class ReportGenerateInput(BaseModel):
    """``report.generate(scan_id, tier, format)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    scan_id: StrictStr = Field(min_length=8, max_length=64)
    tier: ReportTier = ReportTier.MIDGARD
    format: ReportFormat = ReportFormat.JSON


class ReportGenerateResult(BaseModel):
    """Result of ``report.generate``."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: StrictStr = Field(min_length=8, max_length=64)
    scan_id: StrictStr = Field(min_length=8, max_length=64)
    tier: ReportTier
    format: ReportFormat
    queued: StrictBool = True
    audit_event_id: StrictStr | None = Field(default=None, max_length=64)


class ReportDownloadInput(BaseModel):
    """``report.download(report_id)`` arguments."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: StrictStr = Field(min_length=8, max_length=64)
    format: ReportFormat = ReportFormat.JSON


class ReportDownloadResult(BaseModel):
    """Result of ``report.download``.

    The MCP server NEVER streams raw bytes back over the JSON-RPC channel;
    callers receive a *short-lived* presigned URL plus a SHA-256 of the
    final artifact for tamper detection.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    report_id: StrictStr = Field(min_length=8, max_length=64)
    format: ReportFormat
    presigned_url: StrictStr | None = Field(default=None, max_length=2_048)
    sha256: StrictStr | None = Field(
        default=None,
        min_length=64,
        max_length=64,
        description="SHA-256 hex of the report artifact bytes.",
    )
    expires_at: datetime | None = None
    audit_event_id: StrictStr | None = Field(default=None, max_length=64)


__all__ = [
    "ReportDownloadInput",
    "ReportDownloadResult",
    "ReportFormat",
    "ReportGenerateInput",
    "ReportGenerateResult",
    "ReportTier",
]
