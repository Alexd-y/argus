"""Incident Enrichment API — alert-to-code correlation.

POST /api/v1/incidents/enrich      — enrich alert with code context
POST /api/v1/incidents/playbook    — generate remediation playbook
"""

from fastapi import APIRouter
from pydantic import BaseModel
from typing import Any

router = APIRouter(prefix="/incidents", tags=["incidents"])


class EnrichRequest(BaseModel):
    alert: dict[str, Any]
    tenant_id: str = ""
    knowledge_graph_nodes: list[dict[str, Any]] | None = None


class EnrichResponse(BaseModel):
    id: str
    incident_id: str
    alert_id: str
    code_root_cause: str
    file_path: str
    mitre_enrichment: list[dict[str, str]]
    cwe_mapping: list[str]
    remediation_tasks: list[dict[str, Any]]
    confidence: float


@router.post("/enrich", response_model=EnrichResponse)
async def enrich_alert(req: EnrichRequest) -> EnrichResponse:
    from src.workers.incidents.enricher import enrich_incident

    kg = None
    if req.knowledge_graph_nodes:
        from src.knowledge_graph.graph.builder import CodePropertyGraph, GraphNode, NodeType
        kg = CodePropertyGraph(nodes=[
            GraphNode(id=n.get("id", ""), node_type=NodeType(n.get("node_type", "sensitive_sink")),
                     name=n.get("name", ""), file_path=n.get("file_path", ""))
            for n in req.knowledge_graph_nodes
        ])

    result = await enrich_incident(req.alert, kg, tenant_id=req.tenant_id)
    return EnrichResponse(
        id=result.id, incident_id=result.incident_id, alert_id=result.alert_id,
        code_root_cause=result.code_root_cause, file_path=result.file_path,
        mitre_enrichment=result.mitre_enrichment, cwe_mapping=result.cwe_mapping,
        remediation_tasks=result.remediation_tasks, confidence=result.confidence,
    )


@router.post("/playbook")
async def generate_playbook(enriched: EnrichResponse) -> list[dict[str, Any]]:
    from src.workers.incidents.enricher import generate_remediation_playbook, EnrichedAlert

    ea = EnrichedAlert(
        id=enriched.id, incident_id=enriched.incident_id,
        code_root_cause=enriched.code_root_cause,
        remediation_tasks=enriched.remediation_tasks,
    )
    return generate_remediation_playbook(ea)
