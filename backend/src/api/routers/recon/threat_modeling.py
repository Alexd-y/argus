"""Threat modeling API endpoints — runs, execute, trigger, traces, artifacts."""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.db.session import get_db
from src.recon.services.artifact_service import get_artifact_by_engagement_job_filename
from src.recon.services.threat_model_run_service import (
    create_threat_model_run,
    get_engagement,
    get_threat_model_run,
    resolve_recon_dir,
    validate_recon_dir_within_base,
)
from src.recon.threat_modeling.input_loader import (
    load_threat_model_input_bundle_from_artifacts,
)
from src.recon.threat_modeling.pipeline import (
    ThreatModelPipelineError,
    execute_threat_modeling_run,
)

logger = logging.getLogger(__name__)
router = APIRouter(tags=["recon-threat-modeling"])

# Artifact type -> filename mapping for download
ARTIFACT_TYPE_TO_FILENAME: dict[str, str] = {
    "threat_model": "threat_model.md",
    "critical_assets": "critical_assets.csv",
    "entry_points": "entry_points.csv",
    "attacker_profiles": "attacker_profiles.csv",
    "trust_boundaries": "trust_boundaries.csv",
    "trust_boundaries_md": "trust_boundaries.md",
    "application_flows": "application_flows.md",
    "threat_scenarios": "threat_scenarios.csv",
    "testing_priorities": "testing_priorities.md",
    "evidence_gaps": "evidence_gaps.md",
    "ai_reasoning_traces": "ai_reasoning_traces.json",
    "ai_reasoning_trace": "ai_reasoning_traces.json",
    "mcp_trace": "mcp_trace.json",
    "mcp_traces": "mcp_trace.json",
    "ai_tm_critical_assets_normalized": "ai_tm_critical_assets_normalized.json",
    "ai_tm_trust_boundaries_normalized": "ai_tm_trust_boundaries_normalized.json",
    "ai_tm_attacker_profiles_normalized": "ai_tm_attacker_profiles_normalized.json",
    "ai_tm_entry_points_normalized": "ai_tm_entry_points_normalized.json",
    "ai_tm_application_flows_normalized": "ai_tm_application_flows_normalized.json",
    "ai_tm_threat_scenarios_normalized": "ai_tm_threat_scenarios_normalized.json",
    "ai_tm_scenario_scoring_normalized": "ai_tm_scenario_scoring_normalized.json",
    "ai_tm_testing_roadmap_normalized": "ai_tm_testing_roadmap_normalized.json",
    "ai_tm_report_summary_normalized": "ai_tm_report_summary_normalized.json",
}


def _get_tenant_id() -> str:
    return settings.default_tenant_id


class CreateRunBody(BaseModel):
    """Body for creating a threat model run."""

    target_id: str | None = Field(None, description="Optional target ID")
    job_id: str | None = Field(None, description="Optional job ID")


class TriggerBody(BaseModel):
    """Body for trigger (create + execute)."""

    target_id: str | None = Field(None, description="Optional target ID")
    job_id: str | None = Field(None, description="Optional job ID")
    recon_dir: str | None = Field(None, description="Optional recon dir path (file-based)")


@router.post(
    "/recon/engagements/{engagement_id}/threat-modeling/runs",
    status_code=201,
)
async def create_run(
    engagement_id: str,
    body: CreateRunBody | None = None,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    """Create ThreatModelRun (pending, not executed)."""
    tenant_id = _get_tenant_id()
    eng = await get_engagement(db, tenant_id, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")

    run = await create_threat_model_run(
        db,
        tenant_id,
        engagement_id,
        target_id=body.target_id if body else None,
        job_id=body.job_id if body else None,
    )
    return {
        "id": run.id,
        "run_id": run.run_id,
        "job_id": run.job_id,
        "engagement_id": run.engagement_id,
        "target_id": run.target_id,
        "status": run.status,
        "created_at": run.created_at.isoformat() if run.created_at else None,
    }


@router.post(
    "/recon/engagements/{engagement_id}/threat-modeling/runs/{run_id}/execute",
)
async def execute_run(
    engagement_id: str,
    run_id: str,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    """Execute threat modeling pipeline for existing run."""
    tenant_id = _get_tenant_id()
    run = await get_threat_model_run(db, tenant_id, engagement_id, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Threat model run not found")
    if run.status not in ("pending", "failed"):
        raise HTTPException(
            status_code=400,
            detail=f"Run already in status {run.status}. Only pending/failed can be retried.",
        )

    recon_dir: Path | None = None
    eng = await get_engagement(db, tenant_id, engagement_id)
    if eng and eng.scope_config:
        recon_path = resolve_recon_dir(engagement_id, eng.scope_config)
        if recon_path.exists() and recon_path.is_dir():
            recon_dir = recon_path

    try:
        result = await execute_threat_modeling_run(
            engagement_id,
            run.run_id,
            run.job_id,
            target_id=run.target_id,
            recon_dir=recon_dir,
            db=db,
            existing_run_id=run.id,
        )
        return {
            "id": run.id,
            "run_id": result.run_id,
            "job_id": result.job_id,
            "status": result.status,
            "artifact_refs": result.artifact_refs,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        }
    except ThreatModelPipelineError as e:
        logger.warning(
            "Threat model pipeline blocked",
            extra={"engagement_id": engagement_id, "run_id": run_id, "reason": str(e)},
        )
        raise HTTPException(
            status_code=400,
            detail=e.blocking_reason or "blocked",
        ) from e


@router.post(
    "/recon/engagements/{engagement_id}/threat-modeling/trigger",
)
async def trigger(
    engagement_id: str,
    body: TriggerBody | None = None,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    """Create run + execute in one call (Stage 2 trigger)."""
    tenant_id = _get_tenant_id()
    eng = await get_engagement(db, tenant_id, engagement_id)
    if not eng:
        raise HTTPException(status_code=404, detail="Engagement not found")

    target_id = body.target_id if body else None
    job_id = body.job_id if body else None
    recon_dir_str = body.recon_dir if body else None

    recon_dir: Path | None = None
    if recon_dir_str:
        try:
            recon_dir = validate_recon_dir_within_base(recon_dir_str)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail="Invalid recon_dir path",
            ) from None
    elif eng.scope_config:
        recon_path = resolve_recon_dir(engagement_id, eng.scope_config)
        if recon_path.exists() and recon_path.is_dir():
            recon_dir = recon_path

    run = await create_threat_model_run(
        db,
        tenant_id,
        engagement_id,
        target_id=target_id,
        job_id=job_id,
    )

    try:
        result = await execute_threat_modeling_run(
            engagement_id,
            run.run_id,
            run.job_id,
            target_id=target_id,
            recon_dir=recon_dir,
            db=db,
        )
        return {
            "id": run.id,
            "run_id": result.run_id,
            "job_id": result.job_id,
            "status": result.status,
            "artifact_refs": result.artifact_refs,
            "completed_at": result.completed_at.isoformat() if result.completed_at else None,
        }
    except ThreatModelPipelineError as e:
        logger.warning(
            "Threat model pipeline blocked",
            extra={"engagement_id": engagement_id, "run_id": run.id, "reason": str(e)},
        )
        raise HTTPException(
            status_code=400,
            detail=e.blocking_reason or "blocked",
        ) from e


@router.get(
    "/recon/engagements/{engagement_id}/threat-modeling/runs/{run_id}/input-bundle",
)
async def get_input_bundle(
    engagement_id: str,
    run_id: str,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    """Inspect input bundle (from recon artifacts) for this run."""
    tenant_id = _get_tenant_id()
    run = await get_threat_model_run(db, tenant_id, engagement_id, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Threat model run not found")

    eng = await get_engagement(db, tenant_id, engagement_id)
    recon_dir: Path | None = None
    if eng and eng.scope_config:
        recon_path = resolve_recon_dir(engagement_id, eng.scope_config)
        if recon_path.exists() and recon_path.is_dir():
            recon_dir = recon_path

    if recon_dir:
        from src.recon.threat_modeling.input_loader import load_threat_model_input_bundle

        bundle = load_threat_model_input_bundle(recon_dir, engagement_id, run.target_id)
    else:
        bundle = await load_threat_model_input_bundle_from_artifacts(
            db, engagement_id, run.target_id
        )

    return bundle.model_dump(mode="json")


@router.get(
    "/recon/engagements/{engagement_id}/threat-modeling/runs/{run_id}/ai-traces",
)
async def get_ai_traces(
    engagement_id: str,
    run_id: str,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    """Get AI reasoning traces for run."""
    artifact = await _get_trace_artifact(
        db, engagement_id, run_id, "ai_reasoning_traces.json", "AI traces"
    )
    return artifact


@router.get(
    "/recon/engagements/{engagement_id}/threat-modeling/runs/{run_id}/mcp-traces",
)
async def get_mcp_traces(
    engagement_id: str,
    run_id: str,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict:
    """Get MCP traces for run."""
    artifact = await _get_trace_artifact(
        db, engagement_id, run_id, "mcp_trace.json", "MCP traces"
    )
    return artifact


async def _get_trace_artifact(
    db: AsyncSession,
    engagement_id: str,
    run_id: str,
    filename: str,
    label: str,
) -> dict:
    """Get trace artifact content as JSON dict."""
    tenant_id = _get_tenant_id()
    run = await get_threat_model_run(db, tenant_id, engagement_id, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Threat model run not found")

    art = await get_artifact_by_engagement_job_filename(
        db, engagement_id, run.job_id, filename
    )
    if not art:
        raise HTTPException(status_code=404, detail=f"{label} not found for this run")

    from src.recon.storage import download_artifact

    data = download_artifact(art.object_key)
    if not data:
        raise HTTPException(status_code=404, detail="Artifact content unavailable")

    import json

    try:
        return json.loads(data.decode("utf-8"))
    except json.JSONDecodeError as err:
        raise HTTPException(status_code=500, detail="Invalid artifact format") from err


@router.get(
    "/recon/engagements/{engagement_id}/threat-modeling/runs/{run_id}/artifacts/{artifact_type}/download",
)
async def download_artifact_by_type(
    engagement_id: str,
    run_id: str,
    artifact_type: str,
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> Response:
    """Download artifact by type (threat_model, critical_assets, ai_reasoning_traces, etc.)."""
    tenant_id = _get_tenant_id()
    run = await get_threat_model_run(db, tenant_id, engagement_id, run_id)
    if not run:
        raise HTTPException(status_code=404, detail="Threat model run not found")

    filename = ARTIFACT_TYPE_TO_FILENAME.get(artifact_type) or artifact_type
    art = await get_artifact_by_engagement_job_filename(
        db, engagement_id, run.job_id, filename
    )
    if not art:
        raise HTTPException(
            status_code=404,
            detail=f"Artifact '{artifact_type}' not found. Valid types: {list(ARTIFACT_TYPE_TO_FILENAME.keys())[:10]}...",
        )

    from src.recon.storage import download_artifact

    data = download_artifact(art.object_key)
    if not data:
        raise HTTPException(status_code=404, detail="Artifact content unavailable")

    media_type = art.content_type or "application/octet-stream"
    return Response(
        content=data,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{art.filename}"',
        },
    )
