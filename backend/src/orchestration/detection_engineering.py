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
    try:
        from src.orchestration.prompt_loader import get_loader
        loader = get_loader()
        if loader.available:
            try:
                system, user = loader.render_extended_system_user(
                    "detection_engineering", findings_json=findings_json[:50000]
                )
                if system.strip() and user.strip():
                    return system, user
            except Exception:
                pass
    except Exception:
        pass
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


async def run_detection_engineering(
    findings: list[dict[str, Any]],
    llm_executor: Any = None,
    rule_types: list[str] | None = None,
) -> DetectionEngineeringResult:
    """Run the detection engineering co-pilot on findings using an LLM executor.

    Args:
        findings: List of finding dicts from vuln_analysis/exploitation.
        llm_executor: Async callable that accepts (system_prompt, user_prompt)
                      and returns the LLM response dict with 'content' key.
        rule_types: Optional list of rule types to generate (sigma, suricata, waf_modsec).

    Returns:
        DetectionEngineeringResult with generated detection rules.
    """
    if not findings:
        return DetectionEngineeringResult()

    system_prompt, user_prompt = build_detection_prompt(findings)

    if rule_types:
        type_list = ", ".join(rule_types)
        user_prompt += f"\n\nFocus on these rule types: {type_list}"

    if llm_executor is None:
        logger.warning("detection_engineering_no_executor", extra={"findings_count": len(findings)})
        return DetectionEngineeringResult(
            total_findings_processed=len(findings),
            rules_generated=0,
        )

    try:
        result = llm_executor(system_prompt, user_prompt)
        if hasattr(result, "__await__"):
            result = await result
    except Exception as exc:
        logger.warning("detection_engineering_llm_failed", extra={"error": str(exc)})
        return DetectionEngineeringResult(
            total_findings_processed=len(findings),
            rules_generated=0,
        )

    response_text = ""
    if isinstance(result, dict):
        response_text = result.get("content", result.get("text", ""))
    elif isinstance(result, str):
        response_text = result

    if not response_text:
        return DetectionEngineeringResult(total_findings_processed=len(findings))

    try:
        start = response_text.index("{")
        end = response_text.rindex("}") + 1
        parsed = json.loads(response_text[start:end])
    except (ValueError, json.JSONDecodeError):
        logger.warning("detection_engineering_parse_failed")
        return DetectionEngineeringResult(total_findings_processed=len(findings))

    de_result = parse_detection_response(parsed)
    de_result.total_findings_processed = len(findings)
    return de_result


__all__ = [
    "DE_SYSTEM_PROMPT",
    "DE_USER_TEMPLATE",
    "DetectionEngineeringResult",
    "DetectionRule",
    "DetectionRuleType",
    "build_detection_prompt",
    "parse_detection_response",
    "run_detection_engineering",
    "sigma_rule_template",
]