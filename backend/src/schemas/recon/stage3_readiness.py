from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

ROUTE_CLASSIFICATION_CSV_COLUMNS: tuple[str, ...] = (
    "route_path",
    "host",
    "classification",
    "discovery_source",
    "evidence_ref",
)


class Stage3ReadinessStatus(str, Enum):  # noqa: UP042
    READY = "ready"
    NOT_READY = "not_ready"
    PARTIAL = "partial"


class Stage3BlockingReason(str, Enum):  # noqa: UP042
    MISSING_ARTIFACTS = "missing_artifacts"
    INSUFFICIENT_COVERAGE = "insufficient_coverage"
    NO_LIVE_HOSTS = "no_live_hosts"


class CoverageScores(BaseModel):
    subdomain_coverage: float = 0.0
    endpoint_coverage: float = 0.0
    tech_coverage: float = 0.0
    overall: float = 0.0


class Stage3ReadinessResult(BaseModel):
    ready: bool = False
    status: Stage3ReadinessStatus = Stage3ReadinessStatus.NOT_READY
    blocking_reason: str | None = None
    missing_artifacts: list[str] = []
    coverage_scores: CoverageScores | None = None


class Stage3ExecutionReadinessResult(BaseModel):
    ready: bool = False
    blocking_reason: str | None = None
    missing_artifacts: list[str] = []
