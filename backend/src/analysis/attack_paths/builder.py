"""Attack Path Analysis — traces vuln paths from entry point → sink → impact.

Builds visualizable attack chains with evidence backlinks, CVSS-like scoring
with business context, and graph-visualization API output.
"""

from __future__ import annotations

import hashlib
import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class PathNodeType(str, Enum):
    ENTRY_POINT = "entry_point"
    AUTH_BYPASS = "auth_bypass"
    DATA_FLOW = "data_flow"
    SINK = "sink"
    IMPACT = "impact"


class ImpactCategory(str, Enum):
    DATA_BREACH = "data_breach"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    REMOTE_CODE_EXECUTION = "rce"
    DENIAL_OF_SERVICE = "dos"
    INFORMATION_DISCLOSURE = "info_disclosure"
    FINANCIAL_LOSS = "financial_loss"
    COMPLIANCE_VIOLATION = "compliance_violation"
    REPUTATION_DAMAGE = "reputation_damage"


@dataclass
class PathNode:
    id: str = ""
    node_type: PathNodeType = PathNodeType.ENTRY_POINT
    label: str = ""
    file_path: str = ""
    line_start: int = 0
    description: str = ""
    code_snippet: str = ""


@dataclass
class PathEdge:
    source_id: str = ""
    target_id: str = ""
    edge_type: str = ""  # dataflow | auth | transform | exploit
    description: str = ""


@dataclass
class AttackPath:
    id: str = ""
    finding_id: str = ""
    title: str = ""
    severity: str = ""
    nodes: list[PathNode] = field(default_factory=list)
    edges: list[PathEdge] = field(default_factory=list)
    likelihood: float = 0.0
    impact_score: float = 0.0
    overall_risk: float = 0.0
    impact_categories: list[ImpactCategory] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    evidence_backlinks: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class RiskScore:
    id: str = ""
    finding_id: str = ""
    cvss_base: float = 0.0
    cvss_temporal: float = 0.0
    cvss_environmental: float = 0.0
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    business_impact: float = 0.0
    overall_score: float = 0.0
    priority: str = ""  # p1_critical | p2_high | p3_medium | p4_low
    vector_string: str = ""
    reasoning: str = ""


def build_attack_path(
    finding: dict[str, Any],
    knowledge_graph_nodes: list[dict[str, Any]] | None = None,
) -> AttackPath:
    """Build attack path from finding + knowledge graph context.

    Traces: entry_point → auth_bypass/data_flow → sink → impact.
    """
    path = AttackPath(
        id=str(uuid.uuid4()),
        finding_id=finding.get("id", finding.get("finding_id", "")),
        title=finding.get("title", "Untitled"),
        severity=finding.get("severity", "info"),
    )

    entry = finding.get("entry_point") or finding.get("param") or finding.get("url", "")
    sink = finding.get("sink") or finding.get("description", "")[:100]

    if entry:
        path.nodes.append(PathNode(
            id="n1", node_type=PathNodeType.ENTRY_POINT,
            label=f"Entry: {entry[:80]}",
            file_path=finding.get("file_path", ""),
            line_start=finding.get("line_start", 0) or 0,
        ))

    if finding.get("cwe"):
        path.nodes.append(PathNode(
            id="n2", node_type=PathNodeType.AUTH_BYPASS if "auth" in str(finding.get("cwe", "")).lower() else PathNodeType.DATA_FLOW,
            label=f"{finding.get('cwe', '')}: {sink[:80]}",
            file_path=finding.get("file_path", ""),
            line_start=(finding.get("line_start", 0) or 0) + 1,
        ))

    path.nodes.append(PathNode(
        id="n3", node_type=PathNodeType.SINK,
        label=f"Sink: {sink[:80]}",
        file_path=finding.get("file_path", ""),
        line_start=finding.get("line_end", 0) or finding.get("line_start", 0) or 0,
    ))

    impact_labels = _classify_impact(finding)
    path.impact_categories = impact_labels
    path.nodes.append(PathNode(
        id="n4", node_type=PathNodeType.IMPACT,
        label=f"Impact: {', '.join(i.value for i in impact_labels)[:80]}",
    ))

    for i in range(len(path.nodes) - 1):
        path.edges.append(PathEdge(
            source_id=path.nodes[i].id,
            target_id=path.nodes[i + 1].id,
            edge_type="dataflow" if i == 0 else "transform" if i == 1 else "exploit",
        ))

    path.likelihood = _estimate_likelihood(finding)
    path.impact_score = _estimate_impact(finding)
    path.overall_risk = round(path.likelihood * path.impact_score, 2)
    path.assumptions = _extract_assumptions(finding)

    return path


def calculate_risk_score(finding: dict[str, Any], business_context: dict[str, Any] | None = None) -> RiskScore:
    """Calculate CVSS-like risk score with business context."""
    c = business_context or {}

    cvss_base = float(finding.get("cvss", 0.0) or 0.0)
    severity = (finding.get("severity") or "").lower()

    if not cvss_base:
        severity_scores = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
        cvss_base = severity_scores.get(severity, 5.0)

    exploitability = float(finding.get("exploitability_score", 0.0) or 0.0)
    if not exploitability:
        expl_map = {"high": 0.9, "medium": 0.6, "low": 0.3, "unknown": 0.5}
        exploitability = expl_map.get(str(finding.get("exploitability", "unknown")), 0.5)

    cvss_temporal = cvss_base * exploitability

    business_impact = _calculate_business_impact(finding, c)
    cvss_environmental = cvss_temporal * business_impact

    overall = round(cvss_environmental * 10) / 10

    if overall >= 9.0:
        priority = "p1_critical"
    elif overall >= 7.0:
        priority = "p2_high"
    elif overall >= 4.0:
        priority = "p3_medium"
    else:
        priority = "p4_low"

    return RiskScore(
        id=str(uuid.uuid4()),
        finding_id=finding.get("id", finding.get("finding_id", "")),
        cvss_base=cvss_base,
        cvss_temporal=round(cvss_temporal, 1),
        cvss_environmental=round(cvss_environmental, 1),
        exploitability_score=exploitability,
        impact_score=business_impact,
        business_impact=business_impact,
        overall_score=overall,
        priority=priority,
    )


def to_mermaid(path: AttackPath) -> str:
    """Convert attack path to Mermaid graph diagram."""
    lines = ["graph LR"]
    for node in path.nodes:
        safe = node.label.replace('"', "'")[:60]
        lines.append(f'  {node.id}["{safe}"]')
    for edge in path.edges:
        lines.append(f"  {edge.source_id} -->|{edge.edge_type}| {edge.target_id}")
    return "\n".join(lines)


def to_d3_json(path: AttackPath) -> dict[str, Any]:
    """Convert attack path to D3.js-compatible graph JSON."""
    return {
        "nodes": [
            {"id": n.id, "label": n.label, "type": n.node_type.value,
             "file": n.file_path, "line": n.line_start}
            for n in path.nodes
        ],
        "edges": [
            {"source": e.source_id, "target": e.target_id,
             "label": e.edge_type}
            for e in path.edges
        ],
        "metadata": {
            "finding_id": path.finding_id,
            "severity": path.severity,
            "overall_risk": path.overall_risk,
        },
    }


def _classify_impact(finding: dict[str, Any]) -> list[ImpactCategory]:
    desc = (finding.get("description") or "").lower()
    title = (finding.get("title") or "").lower()
    blob = f"{title} {desc}"
    impacts = []
    if any(kw in blob for kw in ("sqli", "sql injection", "data leak", "data breach", "pii")):
        impacts.append(ImpactCategory.DATA_BREACH)
    if any(kw in blob for kw in ("rce", "remote code", "shell", "command injection")):
        impacts.append(ImpactCategory.REMOTE_CODE_EXECUTION)
    if any(kw in blob for kw in ("privilege", "auth bypass", "admin", "escalation")):
        impacts.append(ImpactCategory.PRIVILEGE_ESCALATION)
    if any(kw in blob for kw in ("xss", "csrf", "info disclosure", "information leak")):
        impacts.append(ImpactCategory.INFORMATION_DISCLOSURE)
    if any(kw in blob for kw in ("dos", "denial of service", "crash")):
        impacts.append(ImpactCategory.DENIAL_OF_SERVICE)
    if not impacts:
        impacts.append(ImpactCategory.INFORMATION_DISCLOSURE)
    return impacts


def _estimate_likelihood(finding: dict[str, Any]) -> float:
    confidence = str(finding.get("confidence", "advisory")).lower()
    conf_scores = {"confirmed": 0.9, "likely": 0.7, "possible": 0.4, "advisory": 0.2}
    return conf_scores.get(confidence, 0.5)


def _estimate_impact(finding: dict[str, Any]) -> float:
    severity = str(finding.get("severity", "info")).lower()
    sev_scores = {"critical": 10.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 1.0}
    return sev_scores.get(severity, 5.0)


def _calculate_business_impact(finding: dict[str, Any], ctx: dict[str, Any]) -> float:
    data_classification = ctx.get("data_classification", "internal")
    exposure = ctx.get("exposure", "internal")
    user_base = ctx.get("user_base", 1.0)

    data_scores = {"public": 0.3, "internal": 0.6, "confidential": 0.85, "restricted": 1.0}
    exp_scores = {"internal": 0.5, "external": 0.75, "internet": 1.0}

    return round(
        data_scores.get(data_classification, 0.6) *
        exp_scores.get(exposure, 0.75) *
        min(max(user_base, 0.1), 3.0),
        2,
    )


def _extract_assumptions(finding: dict[str, Any]) -> list[str]:
    return [
        "Attacker has network access to target",
        "No WAF/IDS blocking the payload",
        f"Finding severity {finding.get('severity', 'unknown')} is correct",
    ]
