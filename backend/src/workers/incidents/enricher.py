"""Incident Enrichment Worker — alert-to-code correlation via WhiteRabbitNeo.

Takes: SIEM alerts, IOCs, stack traces.
Produces: code-root-cause mapping, ownership attribution, remediation tasks,
MITRE/CWE/CAPEC enrichment, rollback hints.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.analysis.cpg import CodePropertyGraph, NodeType

logger = logging.getLogger(__name__)


@dataclass
class EnrichedAlert:
    id: str = ""
    incident_id: str = ""
    alert_id: str = ""
    tenant_id: str = ""
    title: str = ""
    severity: str = ""
    iocs: list[dict[str, str]] = field(default_factory=list)
    stack_traces: list[str] = field(default_factory=list)
    affected_services: list[str] = field(default_factory=list)
    code_root_cause: str = ""
    file_path: str = ""
    line_range: str = ""
    owner_team: str = ""
    repo: str = ""
    cloud_asset: str = ""
    mitre_enrichment: list[dict[str, str]] = field(default_factory=list)
    cwe_mapping: list[str] = field(default_factory=list)
    remediation_tasks: list[dict[str, Any]] = field(default_factory=list)
    rollback_hints: list[str] = field(default_factory=list)
    confidence: float = 0.0
    enriched_at: str = ""


def _prompt_incident_enrichment(
    alert: dict[str, Any],
    knowledge_graph: CodePropertyGraph | None,
) -> str:
    iocs = alert.get("iocs", [])
    traces = alert.get("stack_traces", [])
    services = alert.get("affected_services", [])

    kg_sinks = []
    if knowledge_graph:
        kg_sinks = [
            f"  {n.name} @ {n.file_path}:{n.line_start}"
            for n in knowledge_graph.nodes
            if n.node_type == NodeType.SENSITIVE_SINK
        ][:30]

    return f"""Correlate this security alert with potential code root causes.

=== ALERT ===
Title: {alert.get('title', 'N/A')}
Severity: {alert.get('severity', 'unknown')}
Description: {alert.get('description', '')[:1000]}

=== IOCs ===
{json.dumps(iocs[:20], indent=2) if iocs else 'none'}

=== STACK TRACES ===
{chr(10).join(traces[:5]) if traces else 'none'}

=== AFFECTED SERVICES ===
{', '.join(services[:10]) or 'unknown'}

=== KNOWN SENSITIVE SINKS IN CODE ===
{chr(10).join(kg_sinks[:30]) if kg_sinks else 'No code graph available'}

=== TASK ===
Respond with JSON:
{{
  "code_root_cause": "most likely vulnerable code path",
  "file_path": "relevant source file",
  "line_range": "approximate line numbers",
  "mitre_enrichment": [{{"tactic": "...", "technique_id": "T...", "technique": "..."}}],
  "cwe_mapping": ["CWE-..."],
  "remediation_tasks": [{{"title": "...", "assignee": "team", "priority": "p1-p4"}}],
  "rollback_hints": ["specific rollback step"],
  "confidence": 0.0-1.0
}}"""


async def enrich_incident(
    alert: dict[str, Any],
    knowledge_graph: CodePropertyGraph | None = None,
    *,
    tenant_id: str = "",
) -> EnrichedAlert:
    """Enrich a security alert with code-level context via WRB."""
    from src.llm.facade import call_llm_unified
    from src.llm.task_router import LLMTask

    result = EnrichedAlert(
        id=str(uuid.uuid4()),
        incident_id=alert.get("incident_id", ""),
        alert_id=alert.get("alert_id", alert.get("id", "")),
        tenant_id=tenant_id,
        title=alert.get("title", ""),
        severity=alert.get("severity", "unknown"),
        iocs=alert.get("iocs", []),
        stack_traces=alert.get("stack_traces", []),
        affected_services=alert.get("affected_services", []),
    )

    try:
        prompt = _prompt_incident_enrichment(alert, knowledge_graph)
        system = (
            "You are a SOC analyst correlating alerts with code vulnerabilities. "
            "Respond ONLY with valid JSON."
        )
        resp = await call_llm_unified(
            system, prompt,
            task=LLMTask.DEDUP_ANALYSIS,
            phase="incident_enrichment",
        )
        data = json.loads(resp)

        result.code_root_cause = str(data.get("code_root_cause", ""))[:2000]
        result.file_path = str(data.get("file_path", ""))
        result.line_range = str(data.get("line_range", ""))
        result.mitre_enrichment = data.get("mitre_enrichment", [])
        result.cwe_mapping = data.get("cwe_mapping", [])
        result.remediation_tasks = data.get("remediation_tasks", [])
        result.rollback_hints = data.get("rollback_hints", [])
        result.confidence = float(data.get("confidence", 0.5))
        result.enriched_at = datetime.now(timezone.utc).isoformat()
    except Exception as exc:
        logger.warning("incident_enrichment_failed", extra={"error": str(exc)})

    return result


def generate_remediation_playbook(
    enriched: EnrichedAlert,
) -> list[dict[str, Any]]:
    """Generate structured remediation playbook from enriched alert."""
    playbook = []
    for task in enriched.remediation_tasks:
        playbook.append({
            "incident_id": enriched.incident_id,
            "task_id": str(uuid.uuid4()),
            "title": task.get("title", "Unknown task"),
            "priority": task.get("priority", "p3_medium"),
            "assignee": task.get("assignee", "security-team"),
            "status": "pending",
            "code_root_cause": enriched.code_root_cause[:200],
            "rollback_hints": enriched.rollback_hints,
        })
    if not playbook:
        playbook.append({
            "incident_id": enriched.incident_id,
            "task_id": str(uuid.uuid4()),
            "title": f"Investigate {enriched.title[:100]}",
            "priority": "p3_medium",
            "assignee": "security-team",
            "status": "pending",
        })
    return playbook
