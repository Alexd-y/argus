"""Threat Modeling worker v1 — repo-aware STRIDE analysis via WhiteRabbitNeo.

Builds a natural-language threat model from code properties graph, dependency
info, IaC configs, and commit history. Powered exclusively by WhiteRabbitNeo-7B.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from src.analysis.cpg import CodePropertyGraph, NodeType
from src.llm.facade import call_llm_unified
from src.llm.task_router import LLMTask

logger = logging.getLogger(__name__)


@dataclass
class Asset:
    name: str
    asset_type: str  # web_app, api, database, file_store, identity_provider, …
    sensitivity: str  # public, internal, confidential, restricted
    data_types: list[str] = field(default_factory=list)


@dataclass
class AttackSurface:
    name: str
    entry_points: list[str] = field(default_factory=list)
    trust_boundary: str = ""
    auth_mechanism: str = ""


@dataclass
class ThreatScenario:
    id: str = ""
    stride_category: str = ""  # Spoofing | Tampering | Repudiation | InfoDisclosure | DoS | Elevation
    description: str = ""
    affected_assets: list[str] = field(default_factory=list)
    severity: str = ""  # critical | high | medium | low
    likelihood: str = ""  # high | medium | low


@dataclass
class CVEFinding:
    cve_id: str = ""
    description: str = ""
    cvss_score: float = 0.0
    affected_component: str = ""
    remediation: str = ""


@dataclass
class ThreatModel:
    id: str = ""
    tenant_id: str = ""
    repo_id: str = ""
    version: str = "1.0"
    assets: list[Asset] = field(default_factory=list)
    attack_surfaces: list[AttackSurface] = field(default_factory=list)
    threats: list[ThreatScenario] = field(default_factory=list)
    cves: list[CVEFinding] = field(default_factory=list)
    mitigations: list[str] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    created_at: str = ""
    commit_sha: str = ""


def _prompt_threat_model(
    cpg: CodePropertyGraph,
    dependencies: list[dict[str, str]],
    iac_info: dict[str, Any],
    target_name: str,
) -> str:
    """Build WRB prompt for threat modeling from structured inputs."""
    nodes_summary = "\n".join(
        f"  - [{n.node_type.value}] {n.name} @ {n.file_path}:{n.line_start}"
        for n in cpg.nodes[:200]
    )
    entry_points = [n.name for n in cpg.nodes if n.node_type == NodeType.ENTRY_POINT]
    sinks = [n.name for n in cpg.nodes if n.node_type == NodeType.SENSITIVE_SINK]
    functions = [n.name for n in cpg.nodes if n.node_type in (NodeType.FUNCTION, NodeType.METHOD)]

    return f"""Perform a STRIDE threat modeling analysis for: {target_name}

=== CODE PROPERTY GRAPH ===
Files analysed: {len(cpg.nodes)} nodes
Entry points: {', '.join(entry_points[:30]) or 'none detected'}
Sensitive sinks: {', '.join(sinks[:30]) or 'none detected'}
Functions/methods: {', '.join(functions[:50]) or 'none detected'}

Nodes detail:
{nodes_summary}

=== DEPENDENCIES ===
{json.dumps(dependencies[:100], indent=2) if dependencies else 'No dependencies analysed'}

=== INFRASTRUCTURE (IaC) ===
{json.dumps(iac_info, indent=2, default=str) if iac_info else 'No IaC configs analysed'}

=== TASK ===
Output a JSON threat model with:
1. assets: [] — identified critical assets (databases, APIs, auth services, …)
2. attack_surfaces: [] — entry points with trust boundaries and auth mechanisms
3. threats: [] — STRIDE scenarios: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation
4. cves: [] — relevant CVE matches based on component versions
5. mitigations: [] — concrete mitigation recommendations
6. coverage_gaps: [] — what could NOT be determined from available data

Respond ONLY with valid JSON. No markdown, no explanations."""


async def run_threat_modeling(
    repo_name: str,
    cpg: CodePropertyGraph,
    dependencies: list[dict[str, str]],
    iac_info: dict[str, Any],
    *,
    commit_sha: str = "",
    execution_mode: str | None = None,
    scan_options: dict[str, Any] | None = None,
) -> ThreatModel:
    """Run repo-aware threat modeling via WhiteRabbitNeo.

    Args:
        repo_name: Repository name for context.
        cpg: Code Property Graph (AST/CFG/DFG nodes and edges).
        dependencies: Parsed dependency list [{name, version}, …].
        iac_info: Parsed IaC configs (DockerfileInfo, TerraformInfo, …).
        commit_sha: Current commit being analysed.
        execution_mode: Optional ``production`` / ``lab_unrestricted`` for the
            unified LLM gateway. When omitted, facade falls back to scan
            options / contextvar / production.

    Returns:
        ThreatModel with STRIDE scenarios, CVE matches, and mitigations.
    """
    prompt = _prompt_threat_model(cpg, dependencies, iac_info, repo_name)

    system_prompt = (
        "You are an expert application security architect performing STRIDE threat modeling. "
        "You analyse code property graphs, dependencies, and infrastructure configs to identify "
        "security threats, attack surfaces, and CVE-relevant risks. "
        "Respond ONLY with valid JSON matching the requested schema. "
        "Be concrete — reference specific files, functions, and components."
    )

    response_text = await call_llm_unified(
        system_prompt,
        prompt,
        task=LLMTask.THREAT_MODELING,
        phase="threat_modeling",
        execution_mode=execution_mode,
        scan_options=scan_options,
    )

    try:
        data = json.loads(response_text)
    except json.JSONDecodeError:
        # Try extracting JSON from markdown code block
        import re
        match = re.search(r"```(?:json)?\s*([\s\S]*?)```", response_text)
        if match:
            data = json.loads(match.group(1))
        else:
            logger.error("Failed to parse threat model JSON from WRB response")
            data = {}

    model = ThreatModel(
        tenant_id="",
        repo_id="",
        version="1.0",
        commit_sha=commit_sha,
        assets=[Asset(**a) if isinstance(a, dict) else Asset(name=str(a), asset_type="unknown", sensitivity="internal") for a in data.get("assets", [])],
        attack_surfaces=[
            AttackSurface(**s) if isinstance(s, dict) else AttackSurface(name=str(s))
            for s in data.get("attack_surfaces", [])
        ],
        threats=[
            ThreatScenario(**t) if isinstance(t, dict) else ThreatScenario(description=str(t))
            for t in data.get("threats", [])
        ],
        cves=[
            CVEFinding(**c) if isinstance(c, dict) else CVEFinding(cve_id=str(c))
            for c in data.get("cves", [])
        ],
        mitigations=[str(m) for m in data.get("mitigations", [])],
        coverage_gaps=[str(g) for g in data.get("coverage_gaps", [])],
    )
    return model


def build_initial_cpg_from_files(files: dict[str, str]) -> CodePropertyGraph:
    """Build an aggregate code property graph from a set of file paths → content."""
    from src.analysis.cpg import build_cpg

    full_cpg = CodePropertyGraph()
    for file_path, content in files.items():
        try:
            file_cpg = build_cpg(file_path, content)
            full_cpg.nodes.extend(file_cpg.nodes)
            full_cpg.edges.extend(file_cpg.edges)
        except Exception:
            logger.warning("Failed to build CPG for %s", file_path)
    return full_cpg


def build_threat_model_diff(
    previous: ThreatModel,
    current: ThreatModel,
) -> dict[str, Any]:
    """Compute diff between two threat model versions."""
    prev_threat_ids = {t.id or t.description for t in previous.threats}
    curr_threat_ids = {t.id or t.description for t in current.threats}

    return {
        "version": f"{previous.version} → {current.version}",
        "commit": f"{previous.commit_sha} → {current.commit_sha}",
        "new_threats": list(curr_threat_ids - prev_threat_ids),
        "resolved_threats": list(prev_threat_ids - curr_threat_ids),
        "new_cves": [c.cve_id for c in current.cves if c.cve_id not in {p.cve_id for p in previous.cves}],
        "new_attack_surfaces": [s.name for s in current.attack_surfaces if s.name not in {p.name for p in previous.attack_surfaces}],
        "asset_count": {"previous": len(previous.assets), "current": len(current.assets)},
    }
