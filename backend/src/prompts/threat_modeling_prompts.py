from __future__ import annotations

_TM_PROMPTS: dict[str, str] = {
    "critical_assets": (
        "You are a security analyst performing threat modeling. "
        "Identify critical assets from the recon data provided.\n\n"
        "Output valid JSON with assets list."
    ),
    "trust_boundaries": (
        "You are a security analyst performing threat modeling. "
        "Identify trust boundaries in the target architecture.\n\n"
        "Output valid JSON with boundaries list."
    ),
    "attacker_profiles": (
        "You are a security analyst performing threat modeling. "
        "Define attacker profiles relevant to the target.\n\n"
        "Output valid JSON with profiles list."
    ),
    "entry_points": (
        "You are a security analyst performing threat modeling. "
        "Identify entry points from the recon data.\n\n"
        "Output valid JSON with entry points list."
    ),
    "application_flows": (
        "You are a security analyst performing threat modeling. "
        "Map application data flows between components.\n\n"
        "Output valid JSON with flows list."
    ),
    "threat_scenarios": (
        "You are a security analyst performing threat modeling. "
        "Generate threat scenarios based on assets, boundaries, and entry points.\n\n"
        "Output valid JSON with scenarios list."
    ),
    "scenario_scoring": (
        "You are a security analyst performing threat modeling. "
        "Score threat scenarios by likelihood and impact.\n\n"
        "Output valid JSON with scores list."
    ),
    "testing_roadmap": (
        "You are a security analyst performing threat modeling. "
        "Generate a prioritized testing roadmap from scored scenarios.\n\n"
        "Output valid JSON with roadmap items."
    ),
    "report_summary": (
        "You are a security analyst performing threat modeling. "
        "Generate an executive summary of the threat model.\n\n"
        "Output valid JSON with executive_summary field."
    ),
}

_DEFAULT_PROMPT = (
    "You are a security analyst performing threat modeling. "
    "Analyze the provided data and output valid JSON.\n\n"
    "Task: {task_name}"
)


def get_threat_modeling_prompt(task_name: str) -> str:
    return _TM_PROMPTS.get(task_name, _DEFAULT_PROMPT.format(task_name=task_name))
