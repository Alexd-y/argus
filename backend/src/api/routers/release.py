"""Release API — gate checks, delta reports, system cards.

POST /api/v1/release/check        — run release gate check
GET  /api/v1/release/card/{model} — get system card
POST /api/v1/release/delta        — compute eval delta
"""

from typing import Annotated, Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from src.auth.admin_dependencies import require_admin_mfa_passed
from src.auth.admin_sessions import SessionPrincipal

router = APIRouter(prefix="/release", tags=["release"])


class ReleaseCheckRequest(BaseModel):
    model: str = "taico-ai/WhiteRabbitNeo-v3-7B"
    version: str = "1.0.0"
    benchmark_result: dict[str, Any] = {}
    safety_alerts: int = 0
    hallucination_rate: float = 0.0


class DeltaRequest(BaseModel):
    before: dict[str, Any]
    after: dict[str, Any]


@router.post("/check")
async def check_release(req: ReleaseCheckRequest, _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None) -> dict[str, Any]:
    from src.governance.release.gates import check_release_gates

    gates = check_release_gates(
        req.benchmark_result, req.safety_alerts, req.hallucination_rate,
    )
    all_passed = all(g.passed for g in gates)
    return {
        "model": req.model,
        "version": req.version,
        "passed": all_passed,
        "gates": [{"name": g.name, "passed": g.passed, "threshold": g.threshold, "current": g.current_value} for g in gates],
        "verdict": "approved" if all_passed else "blocked",
    }


@router.post("/delta")
async def eval_delta(req: DeltaRequest, _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None) -> dict[str, Any]:
    from src.governance.release.gates import compute_eval_delta

    delta = compute_eval_delta(req.before, req.after)
    return {
        "model_before": delta.model_before,
        "model_after": delta.model_after,
        "precision_delta": delta.precision_delta,
        "recall_delta": delta.recall_delta,
        "f1_delta": delta.f1_delta,
        "false_positive_rate_delta": delta.false_positive_rate_delta,
        "verdict": delta.verdict,
    }


@router.get("/card/{model}")
async def get_system_card(model: str, version: str = "1.0.0", _principal: Annotated[SessionPrincipal, Depends(require_admin_mfa_passed)] = None) -> dict[str, Any]:
    from src.governance.release.gates import generate_system_card

    card = generate_system_card(model, version)
    return {
        "model": card.model,
        "version": card.version,
        "release_date": card.release_date,
        "capabilities": card.capabilities,
        "limitations": card.limitations,
        "risks": card.risks,
        "mitigations": card.mitigations,
        "safety_metrics": card.safety_metrics,
        "review_status": card.review_status,
    }
