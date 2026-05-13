"""Patch Generation API — generate and review security patches.

POST /api/v1/patches/generate    — generate patch for finding
POST /api/v1/patches/generate/batch — batch generation
GET  /api/v1/patches/{id}        — get patch status
POST /api/v1/patches/{id}/validate   — re-validate
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any

router = APIRouter(prefix="/patches", tags=["patches"])


class PatchGenerateRequest(BaseModel):
    finding: dict[str, Any]
    original_code: str
    patch_type: str = "minimal"  # minimal | hardening
    tenant_id: str = ""
    repo_id: str = ""


class PatchResponse(BaseModel):
    id: str
    finding_id: str
    file_path: str
    patch_type: str
    patched_code: str
    diff: str
    rationale: str
    blast_radius: str
    backward_compat_risk: str
    status: str
    lint_passed: bool
    tests_passed: bool
    error: str = ""


@router.post("/generate", response_model=PatchResponse)
async def generate_patch(req: PatchGenerateRequest) -> PatchResponse:
    from src.workers.patches.generator import (
        generate_and_validate_patch, PatchType,
    )

    try:
        ptype = PatchType(req.patch_type)
    except ValueError:
        raise HTTPException(400, f"Unknown patch type: {req.patch_type}")

    result = await generate_and_validate_patch(
        req.finding, req.original_code,
        patch_type=ptype, tenant_id=req.tenant_id, repo_id=req.repo_id,
    )
    return PatchResponse(
        id=result.id,
        finding_id=result.finding_id,
        file_path=result.file_path,
        patch_type=result.patch_type.value,
        patched_code=result.patched_code,
        diff=result.diff,
        rationale=result.rationale,
        blast_radius=result.blast_radius,
        backward_compat_risk=result.backward_compat_risk,
        status=result.status.value,
        lint_passed=result.lint_passed,
        tests_passed=result.tests_passed,
        error=result.error,
    )


@router.post("/generate/batch")
async def generate_patches_batch(
    findings: list[dict[str, Any]],
    patch_type: str = "minimal",
) -> list[PatchResponse]:
    from src.workers.patches.generator import (
        batch_generate_patches, PatchType,
    )

    try:
        ptype = PatchType(patch_type)
    except ValueError:
        raise HTTPException(400, f"Unknown patch type: {patch_type}")

    inputs = [(f, f.get("code_snippet", f.get("original_code", ""))) for f in findings]
    results = await batch_generate_patches(inputs, patch_type=ptype)
    return [
        PatchResponse(
            id=r.id, finding_id=r.finding_id, file_path=r.file_path,
            patch_type=r.patch_type.value, patched_code=r.patched_code,
            diff=r.diff, rationale=r.rationale, blast_radius=r.blast_radius,
            backward_compat_risk=r.backward_compat_risk, status=r.status.value,
            lint_passed=r.lint_passed, tests_passed=r.tests_passed, error=r.error,
        )
        for r in results
    ]
