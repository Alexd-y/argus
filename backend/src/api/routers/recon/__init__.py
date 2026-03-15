"""Recon API routers — aggregates all recon sub-routers."""

from fastapi import APIRouter

from src.api.routers.recon.engagements import router as engagements_router
from src.api.routers.recon.targets import router as targets_router
from src.api.routers.recon.jobs import router as jobs_router
from src.api.routers.recon.artifacts import router as artifacts_router
from src.api.routers.recon.findings import router as findings_router
from src.api.routers.recon.threat_modeling import router as threat_modeling_router
from src.api.routers.recon.vulnerability_analysis import (
    router as vulnerability_analysis_router,
)

recon_router = APIRouter()
recon_router.include_router(engagements_router)
recon_router.include_router(targets_router)
recon_router.include_router(jobs_router)
recon_router.include_router(artifacts_router)
recon_router.include_router(findings_router)
recon_router.include_router(threat_modeling_router)
recon_router.include_router(vulnerability_analysis_router)
