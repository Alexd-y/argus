from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class TechProfileEntry(BaseModel):
    host: str
    indicator_type: str
    value: str
    evidence: str = ""
    confidence: float | None = None


class SslCertEntry(BaseModel):
    common_name: str
    subject_alternative_names: list[str] = []
    issuer: str
    validity_not_before: str
    validity_not_after: str


class AnomalyEntry(BaseModel):
    id: str
    type: str
    source: str
    host: str
    description: str
    evidence: str = ""


class HypothesisEntry(BaseModel):
    id: str
    type: str
    source: str
    text: str


class AnomaliesStructured(BaseModel):
    anomalies: list[AnomalyEntry] = []
    hypotheses: list[HypothesisEntry] = []
    coverage_gaps: list[Any] = []


class ReconResults(BaseModel):
    target_domain: str
    scan_id: str
    generated_at: datetime
    dns: dict[str, dict[str, list[str]]] = {}
    whois: dict[str, Any] | list[Any] = {}
    ssl_certs: dict[str, list[SslCertEntry]] = {}
    tech_stack: list[TechProfileEntry] = []
    http_headers: dict[str, dict[str, Any]] = {}
