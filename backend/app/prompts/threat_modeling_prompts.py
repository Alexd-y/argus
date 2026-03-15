"""Versioned prompt templates for threat modeling AI tasks.

Each prompt instructs the AI to:
- Use ONLY Recon evidence from the provided bundle; do not invent data.
- Tag each output statement as evidence | observation | inference | hypothesis.
- Link evidence_refs to Recon artifact IDs (e.g. endpoint_inventory:row_5, api_surface:path_x).
- Mark assumptions explicitly with statement_type=hypothesis and empty evidence_refs.
"""

from __future__ import annotations

from collections.abc import Callable

PROMPT_VERSION = "1.0.0"

_EVIDENCE_RULES = """
RULES FOR EVIDENCE:
- Use ONLY data from the Recon bundle provided. Do NOT invent or guess.
- For each item, set statement_type to one of: evidence, observation, inference, hypothesis.
- evidence: direct quote or exact match from Recon artifact.
- observation: derived from Recon data with minimal interpretation.
- inference: logical conclusion from Recon data.
- hypothesis: assumption when evidence is insufficient; use empty evidence_refs.
- evidence_refs: reference Recon artifacts (e.g. endpoint_inventory:row_3, api_surface:path_/api, intel_findings:item_0).
- If no Recon evidence supports an item, use statement_type=hypothesis and evidence_refs=[].
"""


def get_critical_assets_prompt() -> str:
    """Prompt for critical_assets task."""
    return f"""Identify critical assets from the Recon bundle.

{_EVIDENCE_RULES}

Output a JSON object with "assets" array. Each asset: id, name, asset_type, description, statement_type, evidence_refs.
Extract assets from: priority_hypotheses, intel_findings, api_surface, endpoint_inventory, tech_profile.
"""


def get_trust_boundaries_prompt() -> str:
    """Prompt for trust_boundaries task."""
    return f"""Identify trust boundaries from the Recon bundle.

{_EVIDENCE_RULES}

Output a JSON object with "boundaries" array. Each boundary: id, name, description, components, statement_type, evidence_refs.
Infer boundaries from: live_hosts, dns_summary, api_surface, endpoint_inventory, anomalies.
"""


def get_attacker_profiles_prompt() -> str:
    """Prompt for attacker_profiles task."""
    return f"""Define attacker profiles relevant to the Recon findings.

{_EVIDENCE_RULES}

Output a JSON object with "profiles" array. Each profile: id, name, capability_level, description, statement_type, evidence_refs.
Base profiles on: intel_findings, anomalies, api_surface, tech_profile (attack surface exposure).
"""


def get_entry_points_prompt() -> str:
    """Prompt for entry_points task."""
    return f"""Identify entry points from the Recon bundle.

{_EVIDENCE_RULES}

Output a JSON object with "entry_points" array. Each entry: id, name, entry_type, host_or_component, description, statement_type, evidence_refs.
Extract from: endpoint_inventory, api_surface, route_inventory, live_hosts.
"""


def get_application_flows_prompt() -> str:
    """Prompt for application_flows task."""
    return f"""Identify data/control flows from the Recon bundle.

{_EVIDENCE_RULES}

Output a JSON object with "flows" array. Each flow: id, source, sink, data_type, description, statement_type, evidence_refs.
Infer from: api_surface, endpoint_inventory, route_inventory, anomalies.
"""


def get_threat_scenarios_prompt() -> str:
    """Prompt for threat_scenarios task."""
    return f"""Generate threat scenarios using assets, boundaries, profiles, entry_points, and flows provided.

{_EVIDENCE_RULES}

Output a JSON object with "scenarios" array. Each scenario: id, title, related_assets, host_component, entry_point, attacker_profile, trust_boundary, description, likelihood, impact, priority, assumptions, recommended_next_manual_checks, statement_type, evidence_refs.
Link each scenario to Recon evidence via evidence_refs. Use hypothesis only when evidence is insufficient.
"""


def get_scenario_scoring_prompt() -> str:
    """Prompt for scenario_scoring task."""
    return f"""Score each threat scenario (likelihood, impact, risk_score).

{_EVIDENCE_RULES}

Output a JSON object with "scores" array. Each score: scenario_id, likelihood, impact, risk_score, statement_type, evidence_refs.
Base scores on scenario content and Recon evidence. Use hypothesis if scoring is largely assumption-based.
"""


def get_testing_roadmap_prompt() -> str:
    """Prompt for testing_roadmap task."""
    return f"""Build a testing roadmap from scenarios and scores.

{_EVIDENCE_RULES}

Output a JSON object with "items" array. Each item: scenario_id, title, priority, recommended_actions, statement_type, evidence_refs.
Prioritize by score. Link each item to scenario and Recon evidence.
"""


def get_report_summary_prompt() -> str:
    """Prompt for report_summary task."""
    return f"""Generate an executive summary of the full threat model.

{_EVIDENCE_RULES}

Output a JSON object with "executive_summary" string (2-4 paragraphs).
Summarize: critical assets, key threats, risk level, recommended next steps.
Base the summary ONLY on the provided full_model data. Do not add unsupported claims.
"""


TM_PROMPT_GETTERS: dict[str, Callable[[], str]] = {
    "critical_assets": get_critical_assets_prompt,
    "trust_boundaries": get_trust_boundaries_prompt,
    "attacker_profiles": get_attacker_profiles_prompt,
    "entry_points": get_entry_points_prompt,
    "application_flows": get_application_flows_prompt,
    "threat_scenarios": get_threat_scenarios_prompt,
    "scenario_scoring": get_scenario_scoring_prompt,
    "testing_roadmap": get_testing_roadmap_prompt,
    "report_summary": get_report_summary_prompt,
}


def get_threat_modeling_prompt(task_name: str) -> str:
    """Return prompt template for the given threat modeling task."""
    if task_name not in TM_PROMPT_GETTERS:
        raise ValueError(f"Unknown threat modeling task: {task_name}")
    return TM_PROMPT_GETTERS[task_name]()
