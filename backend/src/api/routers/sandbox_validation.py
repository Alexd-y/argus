"""Sandbox Validation API — trigger and monitor validation runs.

POST /api/v1/sandbox/validate       — validate one finding
POST /api/v1/sandbox/validate/batch — validate multiple findings
GET  /api/v1/sandbox/runs/{id}      — get run status
GET  /api/v1/sandbox/runs           — list runs
"""

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

router = APIRouter(prefix="/sandbox", tags=["sandbox"])


class ValidateRequest(BaseModel):
    finding_id: str
    finding: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str = ""
    scan_id: str = ""
    profile: str = "web_app"
    timeout_seconds: int = 300
    capture_syscalls: bool = True
    capture_network: bool = False


class ValidateBatchRequest(BaseModel):
    findings: list[dict[str, Any]]
    tenant_id: str = ""
    scan_id: str = ""
    profile: str = "web_app"
    max_concurrent: int = 3


class ValidationResponse(BaseModel):
    id: str
    finding_id: str
    status: str
    exploitable: bool
    confidence: float
    exit_code: int
    duration_ms: int
    error: str = ""


@router.post("/validate", response_model=ValidationResponse)
async def validate_finding(req: ValidateRequest) -> ValidationResponse:
    from src.sandbox.validation.orchestrator import (
        ValidationConfig,
        ValidationOrchestrator,
        ValidationProfile,
    )

    try:
        profile = ValidationProfile(req.profile)
    except ValueError:
        raise HTTPException(400, f"Unknown profile: {req.profile}")

    config = ValidationConfig(
        profile=profile,
        timeout_seconds=req.timeout_seconds,
        capture_syscalls=req.capture_syscalls,
        capture_network=req.capture_network,
    )
    orch = ValidationOrchestrator(
        tenant_id=req.tenant_id,
        scan_id=req.scan_id,
    )
    result = await orch.validate(req.finding, config)
    return ValidationResponse(
        id=result.id,
        finding_id=result.finding_id,
        status=result.status.value,
        exploitable=result.exploitable,
        confidence=result.confidence,
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        error=result.error,
    )


@router.post("/validate/batch")
async def validate_batch(req: ValidateBatchRequest) -> list[ValidationResponse]:
    from src.sandbox.validation.orchestrator import (
        ValidationConfig,
        ValidationOrchestrator,
        ValidationProfile,
    )

    try:
        profile = ValidationProfile(req.profile)
    except ValueError:
        raise HTTPException(400, f"Unknown profile: {req.profile}")

    config = ValidationConfig(profile=profile)
    orch = ValidationOrchestrator(
        tenant_id=req.tenant_id,
        scan_id=req.scan_id,
    )
    results = await orch.validate_batch(
        req.findings, config, max_concurrent=req.max_concurrent,
    )
    return [
        ValidationResponse(
            id=r.id, finding_id=r.finding_id, status=r.status.value,
            exploitable=r.exploitable, confidence=r.confidence,
            exit_code=r.exit_code, duration_ms=r.duration_ms, error=r.error,
        )
        for r in results
    ]
