"""Compliance API — audit reports and evidence.

POST /api/v1/compliance/map        — map finding to frameworks
GET  /api/v1/compliance/report     — build audit report
"""

from fastapi import APIRouter, Query
from pydantic import BaseModel
from typing import Any

router = APIRouter(prefix="/compliance", tags=["compliance"])


class ComplianceMapRequest(BaseModel):
    finding: dict[str, Any]
    tenant_id: str = ""
    frameworks: list[str] = ["iso27001", "soc2"]


@router.post("/map")
async def map_finding(req: ComplianceMapRequest) -> list[dict[str, Any]]:
    from src.governance.compliance.mapper import map_finding_to_compliance, Framework

    frameworks = []
    for fw in req.frameworks:
        try:
            frameworks.append(Framework(fw))
        except ValueError:
            pass

    evidence = await map_finding_to_compliance(
        req.finding, tenant_id=req.tenant_id, frameworks=frameworks or None,
    )
    return [
        {
            "finding_id": e.finding_id, "framework": e.framework,
            "control_id": e.control_id, "evidence_type": e.evidence_type,
            "evidence_description": e.evidence_description,
            "evidence_hash": e.evidence_hash,
            "validity_days": e.validity_days,
        }
        for e in evidence
    ]


@router.post("/report")
async def build_report(
    findings: list[dict[str, Any]],
    tenant_id: str = "",
    frameworks: list[str] = ["iso27001", "soc2"],
) -> dict[str, Any]:
    from src.governance.compliance.mapper import build_audit_report, Framework

    fw_list = []
    for f in frameworks:
        try:
            fw_list.append(Framework(f))
        except ValueError:
            pass

    return build_audit_report(findings, tenant_id=tenant_id, frameworks=fw_list or None)
