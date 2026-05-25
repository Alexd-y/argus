"""Detection engineering co-pilot — generate Sigma/Suricata/WAF rules from findings.

Translates vulnerability findings into actionable detection artifacts:
- Sigma rules for SIEM
- Suricata signatures for IDS
- WAF rules (ModSecurity/OpenAppSec)

Ось F п.3 из Развитие2.md: detection engineering co-pilot.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


class DetectionRuleType:
    SIGMA = "sigma"
    SURICATA = "suricata"
    WAF_MODSEC = "waf_modsec"
    WAF_OPENAPPSEC = "waf_openappsec"


@dataclass
class DetectionRule:
    """A generated detection rule from a finding."""

    rule_type: str
    title: str
    rule_content: str
    finding_id: str
    severity: str = "medium"
    references: list[str] = field(default_factory=list)


@dataclass
class DetectionEngineeringResult:
    """Result of the detection engineering co-pilot."""

    rules: list[DetectionRule] = field(default_factory=list)
    total_findings_processed: int = 0
    rules_generated: int = 0


DE_SYSTEM_PROMPT = (
    "You are a detection engineer generating defensive rules from pentest findings.\n"
    "Create Sigma rules, Suricata signatures, and WAF rules that detect the "
    "attack patterns identified in the findings.\n"
    "Rules must be production-ready: no false positives on legitimate traffic.\n"
    "Respond ONLY with valid JSON."
)

DE_USER_TEMPLATE = (
    "Generate detection rules from the following pentest findings.\n\n"
    "=== FINDINGS ===\n{findings_json}\n=== END ===\n\n"
    "For each exploitable finding, generate:\n"
    "1. A Sigma rule for SIEM detection\n"
    "2. A Suricata signature for IDS\n"
    "3. A WAF rule for web application firewall\n\n"
    'Return JSON: {{"rules": [{{"rule_type": "sigma|suricata|waf_modsec", '
    '"title": "s", "rule_content": "s", "finding_id": "s", "severity": "s", '
    '"references": ["s"]}}]}}'
)


def build_detection_prompt(findings: list[dict[str, Any]]) -> tuple[str, str]:
    """Build the detection engineering prompt from findings."""
    findings_json = json.dumps(findings, default=str, ensure_ascii=False)
    user = DE_USER_TEMPLATE.format(findings_json=findings_json[:50000])
    return DE_SYSTEM_PROMPT, user


def parse_detection_response(response_data: dict[str, Any]) -> DetectionEngineeringResult:
    """Parse the LLM response from the detection engineering co-pilot."""
    rules = []
    for item in response_data.get("rules", []):
        rules.append(DetectionRule(
            rule_type=item.get("rule_type", "sigma"),
            title=item.get("title", ""),
            rule_content=item.get("rule_content", ""),
            finding_id=item.get("finding_id", ""),
            severity=item.get("severity", "medium"),
            references=item.get("references", []),
        ))
    return DetectionEngineeringResult(
        rules=rules,
        total_findings_processed=0,
        rules_generated=len(rules),
    )


def sigma_rule_template(
    title: str,
    description: str,
    detection: str,
    level: str = "medium",
    references: list[str] | None = None,
) -> str:
    """Generate a basic Sigma rule YAML structure."""
    refs_yaml = ""
    if references:
        refs_yaml = "\n".join(f"    - {r}" for r in references)
        refs_yaml = f"references:\n{refs_yaml}\n"
    return (
        f"title: {title}\n"
        f"description: {description}\n"
        f"status: experimental\n"
        f"level: {level}\n"
        f"{refs_yaml}"
        f"detection:\n"
        f"  {detection}\n"
        f"  condition: selection\n"
    )


__all__ = [
    "DE_SYSTEM_PROMPT",
    "DE_USER_TEMPLATE",
    "DetectionEngineeringResult",
    "DetectionRule",
    "DetectionRuleType",
    "build_detection_prompt",
    "parse_detection_response",
    "sigma_rule_template",
]