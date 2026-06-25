"""Pydantic schemas for Stage 1 recon artifacts."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


# --- DNS record types (whitelist for validation)
DnsRecordType = Literal["A", "AAAA", "CNAME", "MX", "TXT", "NS"]


class TechProfileEntry(BaseModel):
    """Tech profile entry per host."""

    model_config = ConfigDict(extra="forbid")

    host: str = Field(min_length=1, max_length=512)
    indicator_type: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=1, max_length=1024)
    evidence: str = Field(default="", max_length=2000)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class SslCertEntry(BaseModel):
    """Single SSL certificate entry for a host."""

    model_config = ConfigDict(extra="forbid")

    common_name: str = Field(min_length=1, max_length=512)
    subject_alternative_names: list[str] = Field(default_factory=list, max_length=200)
    issuer: str = Field(min_length=1, max_length=512)
    validity_not_before: datetime
    validity_not_after: datetime

    @model_validator(mode="after")
    def validate_validity_order(self) -> "SslCertEntry":
        if self.validity_not_before >= self.validity_not_after:
            raise ValueError("validity_not_before must be before validity_not_after")
        return self


class ReconResults(BaseModel):
    """Unified recon data from Stage 1."""

    model_config = ConfigDict(extra="forbid")

    target_domain: str = Field(min_length=1, max_length=253)
    scan_id: str = Field(min_length=1, max_length=200)
    generated_at: datetime

    dns: dict[str, dict[str, list[str]]] = Field(
        default_factory=dict,
        description="DNS records by domain/subdomain: {domain: {record_type: [values]}}",
    )
    whois: dict[str, Any] | list[Any] = Field(
        default_factory=dict,
        description="Full WHOIS data (dict or list). Default: {} when omitted.",
    )
    ssl_certs: dict[str, list[SslCertEntry]] = Field(
        default_factory=dict,
        description="SSL cert entries per host: {host: [SslCertEntry]}",
    )
    tech_stack: list[TechProfileEntry] = Field(
        default_factory=list,
        max_length=2000,
        description="Tech profile entries per host",
    )
    http_headers: dict[str, dict[str, Any]] = Field(
        default_factory=dict,
        description="Headers analysis per host: {host: {header_name: value}}",
    )


class McpTraceEvent(BaseModel):
    """MCP audit log entry for tool execution trace."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    tool_name: str = Field(min_length=1, max_length=200)
    input_parameters: dict[str, Any] = Field(
        default_factory=dict,
        description="Input params including target. Do not log/store passwords, tokens, keys.",
    )
    output_summary: str | None = Field(default=None, max_length=10000)
    run_id: str = Field(min_length=1, max_length=200)
    job_id: str = Field(min_length=1, max_length=200)
    status: Literal["success", "error"] = Field(
        description="Execution status",
    )


class AnomalyEntry(BaseModel):
    """Single anomaly for AI analysis."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    type: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=256)
    host: str = Field(min_length=1, max_length=512)
    description: str = Field(min_length=1, max_length=2000)
    evidence: str = Field(default="", max_length=2000)


class HypothesisEntry(BaseModel):
    """Single hypothesis for AI analysis."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=100)
    type: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=256)
    text: str = Field(min_length=1, max_length=5000)


class AnomaliesStructured(BaseModel):
    """Anomalies and hypotheses for AI analysis."""

    model_config = ConfigDict(extra="forbid")

    anomalies: list[AnomalyEntry] = Field(default_factory=list, max_length=500)
    hypotheses: list[HypothesisEntry] = Field(default_factory=list, max_length=200)
    coverage_gaps: list[str | dict[str, Any]] = Field(
        default_factory=list,
        max_length=200,
        description="Coverage gaps as strings or structured entries",
    )
