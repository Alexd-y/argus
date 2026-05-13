"""Risk Scoring API — calculate priority and build attack paths.

POST /api/v1/analysis/score        — calculate risk score
POST /api/v1/analysis/path         — build attack path
POST /api/v1/analysis/batch        — batch scoring + paths
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any

router = APIRouter(prefix="/analysis", tags=["analysis"])


class ScoreRequest(BaseModel):
    finding: dict[str, Any]
    business_context: dict[str, Any] | None = None


class ScoreResponse(BaseModel):
    finding_id: str
    cvss_base: float
    cvss_environmental: float
    overall_score: float
    priority: str
    reasoning: str = ""


class PathRequest(BaseModel):
    finding: dict[str, Any]
    format: str = "json"  # json | mermaid


class PathResponse(BaseModel):
    finding_id: str
    severity: str
    overall_risk: float
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    mermaid: str = ""


@router.post("/score", response_model=ScoreResponse)
async def calculate_score(req: ScoreRequest) -> ScoreResponse:
    from src.analysis.attack_paths.builder import calculate_risk_score

    score = calculate_risk_score(req.finding, req.business_context)
    return ScoreResponse(
        finding_id=score.finding_id,
        cvss_base=score.cvss_base,
        cvss_environmental=score.cvss_environmental,
        overall_score=score.overall_score,
        priority=score.priority,
        reasoning=score.reasoning,
    )


@router.post("/path", response_model=PathResponse)
async def build_path(req: PathRequest) -> PathResponse:
    from src.analysis.attack_paths.builder import (
        build_attack_path, to_mermaid, to_d3_json,
    )

    path = build_attack_path(req.finding)
    graph = to_d3_json(path)

    return PathResponse(
        finding_id=path.finding_id,
        severity=path.severity,
        overall_risk=path.overall_risk,
        nodes=graph["nodes"],
        edges=graph["edges"],
        mermaid=to_mermaid(path),
    )


@router.post("/batch")
async def analyse_batch(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    from src.analysis.attack_paths.builder import (
        calculate_risk_score, build_attack_path, to_d3_json,
    )

    results = []
    for f in findings:
        score = calculate_risk_score(f)
        path = build_attack_path(f)
        graph = to_d3_json(path)
        results.append({
            "finding_id": f.get("id", ""),
            "risk_score": {
                "overall": score.overall_score,
                "priority": score.priority,
                "cvss": score.cvss_base,
            },
            "attack_path": graph,
        })
    return results
