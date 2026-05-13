"""Research Workbench — analyst tools for defenders.

Provides: advisories summary, exploit class explanation, defensive runbooks,
tabletop scenarios, model version comparison.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AdvisorySummary:
    id: str = ""
    cve_id: str = ""
    title: str = ""
    severity: str = ""
    summary: str = ""
    affected_versions: list[str] = field(default_factory=list)
    patches: list[str] = field(default_factory=list)
    exploit_available: bool = False
    recommendations: list[str] = field(default_factory=list)


@dataclass
class DefensiveRunbook:
    id: str = ""
    title: str = ""
    severity: str = ""
    steps: list[dict[str, str]] = field(default_factory=list)
    rollback_plan: list[str] = field(default_factory=list)
    verification: list[str] = field(default_factory=list)


@dataclass
class TabletopScenario:
    id: str = ""
    title: str = ""
    scenario_type: str = ""   # ransomware | data_breach | apt | insider | supply_chain
    description: str = ""
    objectives: list[str] = field(default_factory=list)
    injects: list[dict[str, str]] = field(default_factory=list)
    duration_minutes: int = 60
    participants: list[str] = field(default_factory=list)


async def summarise_advisory(cve_id: str, description: str) -> AdvisorySummary:
    from src.llm.facade import call_llm_unified
    from src.llm.task_router import LLMTask

    prompt = f"""Summarise this security advisory for defenders.

=== CVE ===
{cve_id}

=== DESCRIPTION ===
{description[:2000]}

Respond with JSON: {{"summary": "...", "severity": "critical|high|medium|low", "affected_versions": [...], "patches": [...], "exploit_available": true/false, "recommendations": [...]}}"""

    try:
        resp = await call_llm_unified(
            "You summarise CVEs for security teams. Output JSON.",
            prompt, task=LLMTask.REPORT_SECTION, phase="advisory_summary",
        )
        data = json.loads(resp)
        return AdvisorySummary(
            id=str(uuid.uuid4()), cve_id=cve_id,
            title=data.get("summary", cve_id)[:200],
            severity=data.get("severity", "medium"),
            summary=data.get("summary", "")[:1000],
            affected_versions=data.get("affected_versions", []),
            patches=data.get("patches", []),
            exploit_available=data.get("exploit_available", False),
            recommendations=data.get("recommendations", []),
        )
    except Exception:
        return AdvisorySummary(id=str(uuid.uuid4()), cve_id=cve_id, title=cve_id, severity="unknown")


async def generate_defensive_runbook(
    finding_type: str, environment: str = "kubernetes",
) -> DefensiveRunbook:
    from src.llm.facade import call_llm_unified
    from src.llm.task_router import LLMTask

    prompt = f"""Create a defensive runbook for: {finding_type} in {environment}.

Respond with JSON:
{{"title": "...", "steps": [{{"step": 1, "action": "...", "owner": "team", "tools": ["..."]}}], "rollback_plan": ["..."], "verification": ["..."]}}"""

    try:
        resp = await call_llm_unified(
            "You create security runbooks. Output JSON.",
            prompt, task=LLMTask.REMEDIATION_PLAN, phase="runbook_generation",
        )
        data = json.loads(resp)
        return DefensiveRunbook(
            id=str(uuid.uuid4()), title=data.get("title", finding_type),
            severity="high", steps=data.get("steps", []),
            rollback_plan=data.get("rollback_plan", []),
            verification=data.get("verification", []),
        )
    except Exception:
        return DefensiveRunbook(id=str(uuid.uuid4()), title=finding_type, severity="medium")


async def generate_tabletop_scenario(
    scenario_type: str = "ransomware", organisation_size: str = "medium",
) -> TabletopScenario:
    from src.llm.facade import call_llm_unified
    from src.llm.task_router import LLMTask

    prompt = f"""Design a tabletop exercise scenario: {scenario_type} for a {organisation_size} organisation.

Respond with JSON:
{{"title": "...", "description": "...", "objectives": [...], "injects": [{{"time": "HH:MM", "event": "..."}}], "duration_minutes": 60, "participants": [...]}}"""

    try:
        resp = await call_llm_unified(
            "You design cybersecurity tabletop exercises. Output JSON.",
            prompt, task=LLMTask.REMEDIATION_PLAN, phase="tabletop_design",
        )
        data = json.loads(resp)
        return TabletopScenario(
            id=str(uuid.uuid4()), title=data.get("title", scenario_type.title()),
            scenario_type=scenario_type,
            description=data.get("description", "")[:2000],
            objectives=data.get("objectives", []),
            injects=data.get("injects", []),
            duration_minutes=data.get("duration_minutes", 60),
            participants=data.get("participants", ["CISO", "SOC Lead", "IR Team", "Legal", "PR"]),
        )
    except Exception:
        return TabletopScenario(id=str(uuid.uuid4()), title=scenario_type.title(), scenario_type=scenario_type)


async def explain_exploit_class(vuln_type: str) -> str:
    from src.llm.facade import call_llm_unified
    from src.llm.task_router import LLMTask

    prompt = f"""Explain the {vuln_type} vulnerability class at a high level for security analysts.
Cover: how it works, common attack vectors, detection methods, and prevention.
Keep under 500 words."""

    try:
        return await call_llm_unified(
            "You explain security concepts clearly. Be concise.", prompt,
            task=LLMTask.REMEDIATION_PLAN, phase="exploit_explanation",
        )
    except Exception:
        return f"Unable to explain {vuln_type} at this time."


def compare_models(models: list[str], benchmark_results: dict[str, dict[str, Any]]) -> dict[str, Any]:
    comparison = {}
    for model, results in benchmark_results.items():
        comparison[model] = {
            "precision": results.get("overall_precision", 0),
            "recall": results.get("overall_recall", 0),
            "f1": results.get("overall_f1", 0),
            "false_positive_rate": results.get("false_positive_rate", 0),
            "patch_acceptance": results.get("patch_acceptance_rate", 0),
        }

    best = sorted(comparison.items(), key=lambda x: x[1]["f1"], reverse=True)
    return {
        "ranking": [model for model, _ in best],
        "details": comparison,
        "best_overall": best[0][0] if best else "unknown",
    }
