"""Binary Clustering — YARA/Sigma rule generation, ATT&CK mapping via WhiteRabbitNeo.

Generates: YARA rules for family detection, Sigma rules for SIEM, MITRE ATT&CK mapping.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class YARARule:
    name: str = ""
    description: str = ""
    strings: list[str] = field(default_factory=list)
    condition: str = "any of them"


@dataclass
class SigmaRule:
    title: str = ""
    id: str = ""
    description: str = ""
    status: str = "experimental"
    level: str = "medium"
    logsource: dict[str, str] = field(default_factory=dict)
    detection: dict[str, Any] = field(default_factory=dict)


@dataclass
class ATTACKMapping:
    tactic: str = ""
    technique_id: str = ""
    technique: str = ""
    subtechnique_id: str = ""
    procedure: str = ""


async def generate_yara_rules(
    indicators: list[str], metadata: dict[str, Any],
) -> list[YARARule]:
    """Generate YARA rules for binary family via WRB."""
    from src.llm.facade import call_llm_unified
    from src.llm.task_router import LLMTask

    prompt = f"""Generate YARA detection rule for this malware sample.

=== INDICATORS ===
Strings: {', '.join(indicators[:30])}
File type: {metadata.get('format', 'unknown')}
Capabilities: {', '.join(metadata.get('capabilities', []))}

=== OUTPUT ===
JSON: {{"name": "rule_name", "description": "...",
"strings": ["$s1 = \\"string1\\"", ...],
"condition": "any of them"}}"""

    try:
        resp = await call_llm_unified(
            "You generate YARA rules for malware detection. Output valid JSON.",
            prompt, task=LLMTask.EXPLOIT_GENERATION, phase="yara_generation",
        )
        data = json.loads(resp)
        return [YARARule(**data)]
    except Exception:
        return []


async def generate_sigma_rule(
    technique_id: str, indicators: list[str],
) -> SigmaRule | None:
    """Generate Sigma rule for SIEM from ATT&CK technique."""
    return SigmaRule(
        title=f"{technique_id} detection",
        id=str(uuid.uuid4()),
        description=f"Detect {technique_id} activity",
    )


def map_to_attck(capabilities: list[str]) -> list[ATTACKMapping]:
    """Map binary capabilities to MITRE ATT&CK."""
    cap_to_attck = {
        "creates_process": ATTACKMapping(tactic="Execution", technique_id="T1059", technique="Command and Scripting Interpreter"),
        "network_communication": ATTACKMapping(tactic="Command and Control", technique_id="T1071", technique="Application Layer Protocol"),
        "file_manipulation": ATTACKMapping(tactic="Defense Evasion", technique_id="T1564", technique="Hide Artifacts"),
        "registry_modification": ATTACKMapping(tactic="Persistence", technique_id="T1547", technique="Boot or Logon Autostart Execution"),
        "credential_access": ATTACKMapping(tactic="Credential Access", technique_id="T1003", technique="OS Credential Dumping"),
        "defense_evasion": ATTACKMapping(tactic="Defense Evasion", technique_id="T1055", technique="Process Injection"),
        "persistence": ATTACKMapping(tactic="Persistence", technique_id="T1053", technique="Scheduled Task/Job"),
        "c2_communication": ATTACKMapping(tactic="Command and Control", technique_id="T1573", technique="Encrypted Channel"),
        "data_exfiltration": ATTACKMapping(tactic="Exfiltration", technique_id="T1041", technique="Exfiltration Over C2 Channel"),
    }
    mappings = []
    for cap in capabilities:
        m = cap_to_attck.get(cap)
        if m:
            mappings.append(m)
    return mappings
