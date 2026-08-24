"""Binary Triage API — analyse binary samples.

POST /api/v1/binary/analyse        — static + WRB analysis
POST /api/v1/binary/dynamic        — dynamic sandbox execution
POST /api/v1/binary/quarantine     — custody chain
POST /api/v1/binary/yara           — generate YARA rules
"""

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/binary", tags=["binary"])


class BinaryAnalyseRequest(BaseModel):
    file_path: str = ""
    tenant_id: str = ""
    sample_id: str = ""


class BinaryAnalyseResponse(BaseModel):
    id: str
    sample_id: str
    format: str
    verdict: str
    risk_score: float
    architecture: str
    capabilities: list[str]
    mitre_attck: list[dict[str, str]]
    indicators: list[dict[str, str]]
    sha256: str = ""
    error: str = ""


@router.post("/analyse", response_model=BinaryAnalyseResponse)
async def analyse_binary(req: BinaryAnalyseRequest) -> BinaryAnalyseResponse:
    from src.workers.binary.static.analyser import analyse_binary as do_analyse

    result = await do_analyse(
        req.file_path, tenant_id=req.tenant_id, sample_id=req.sample_id,
    )
    return BinaryAnalyseResponse(
        id=result.id, sample_id=result.sample_id,
        format=result.metadata.format.value,
        verdict=result.verdict, risk_score=result.risk_score,
        architecture=result.metadata.architecture,
        capabilities=result.metadata.capabilities,
        mitre_attck=result.mitre_attck,
        indicators=result.indicators,
        sha256=result.metadata.sha256,
        error=result.error,
    )


@router.post("/dynamic")
async def dynamic_analysis(req: BinaryAnalyseRequest) -> dict[str, Any]:
    from src.workers.binary.dynamic.lab import run_dynamic_analysis

    result = await run_dynamic_analysis(req.file_path, tenant_id=req.tenant_id)
    return {
        "id": result.id, "sample_id": result.sample_id,
        "execution_time_ms": result.execution_time_ms,
        "exit_code": result.exit_code, "verdict": result.verdict,
        "error": result.error,
    }


@router.post("/quarantine")
async def quarantine(req: BinaryAnalyseRequest) -> dict[str, Any]:
    from src.workers.binary.dynamic.lab import quarantine_sample

    record = await quarantine_sample(req.file_path, tenant_id=req.tenant_id)
    return {
        "id": record.id, "sample_id": record.sample_id,
        "status": record.status, "hash_before": record.hash_before,
    }


@router.post("/yara")
async def generate_yara(indicators: list[str], metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    from src.workers.binary.clustering.yara_sigma import generate_yara_rules

    rules = await generate_yara_rules(indicators, metadata or {})
    return {"rules": [{"name": r.name, "strings": r.strings[:20], "condition": r.condition} for r in rules]}
