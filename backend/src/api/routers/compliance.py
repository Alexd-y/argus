"""Compliance API — audit reports and evidence.

POST /api/v1/compliance/map        — map finding to frameworks
GET  /api/v1/compliance/report     — build audit report
"""

import contextlib
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(prefix="/compliance", tags=["compliance"])


class ComplianceMapRequest(BaseModel):
    finding: dict[str, Any]
    tenant_id: str = ""
    frameworks: list[str] = ["iso27001", "soc2"]


@router.post("/map")
async def map_finding(req: ComplianceMapRequest) -> list[dict[str, Any]]:
    from src.governance.compliance.mapper import Framework, map_finding_to_compliance

    frameworks = []
    for fw in req.frameworks:
        with contextlib.suppress(ValueError):
            frameworks.append(Framework(fw))

    evidence = await map_finding_to_compliance(
        req.finding,
        tenant_id=req.tenant_id,
        frameworks=frameworks or None,
    )
    return [
        {
            "finding_id": e.finding_id,
            "framework": e.framework,
            "control_id": e.control_id,
            "evidence_type": e.evidence_type,
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
    frameworks: list[str] = None,
) -> dict[str, Any]:
    from src.governance.compliance.mapper import Framework, build_audit_report

    if frameworks is None:
        frameworks = ["iso27001", "soc2"]
    fw_list = []
    for f in frameworks:
        with contextlib.suppress(ValueError):
            fw_list.append(Framework(f))

    return build_audit_report(findings, tenant_id=tenant_id, frameworks=fw_list or None)
