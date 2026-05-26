"""Adversarial Critic agent — red-team review of pentest plans and findings.

Reviews the vulnerability analysis plan from the attacker's perspective:
"How would an attacker bypass this finding?" "What did we miss?" "What
assumptions are wrong?" Produces critique that improves final report quality.

Ось D п.4 из Развитие2.md: adversarial critic agent.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class CritiqueItem:
    """A single critique from the adversarial review."""

    finding_id: str
    critique_type: str
    description: str
    suggested_action: str
    severity: str = "medium"


@dataclass
class AdversarialCritiqueResult:
    """Result of the adversarial critic review."""

    findings_reviewed: int
    critiques: list[CritiqueItem] = field(default_factory=list)
    blind_spots: list[str] = field(default_factory=list)
    assumptions_challenged: list[str] = field(default_factory=list)
    overall_assessment: str = ""


CRITIC_SYSTEM_PROMPT = (
    "You are a red-team critic reviewing a penetration test from the ATTACKER'S perspective.\n"
    "For each finding, ask: How would an attacker bypass this? What did we miss?\n"
    "What assumptions might be wrong? What alternative exploitation paths exist?\n"
    "Be constructive — identify gaps and suggest improvements.\n"
    "NEVER fabricate vulnerabilities. Only challenge real findings with real reasoning."
)

CRITIC_USER_TEMPLATE = (
    "Review the following pentest findings from an adversarial perspective.\n\n"
    "=== FINDINGS ===\n{findings_json}\n=== END ===\n\n"
    "For each finding, consider:\n"
    "1. BYPASS: How could an attacker circumvent the stated vulnerability or its remediation?\n"
    "2. BLIND SPOTS: What related attack vectors did the scan miss?\n"
    "3. ASSUMPTIONS: What unstated assumptions does this finding rely on?\n"
    "4. CHAINING: Can this finding be combined with others for greater impact?\n\n"
    'Return JSON: {{"critiques": [{{"finding_id": "s", "critique_type": "bypass|blind_spot|assumption|chaining", '
    '"description": "s", "suggested_action": "s", "severity": "high|medium|low"}}], '
    '"blind_spots": ["s"], "assumptions_challenged": ["s"], "overall_assessment": "s"}}'
)


def build_critic_prompt(findings: list[dict[str, Any]]) -> tuple[str, str]:
    """Build the adversarial critic prompt from findings.

    Returns (system_prompt, user_prompt).
    """
    findings_json = json.dumps(findings, default=str, ensure_ascii=False)
    try:
        from src.orchestration.prompt_loader import get_loader
        loader = get_loader()
        if loader.available:
            try:
                system, user = loader.render_extended_system_user(
                    "adversarial_critic", findings_json=findings_json[:50000]
                )
                if system.strip() and user.strip():
                    return system, user
            except Exception:
                pass
    except Exception:
        pass
    user = CRITIC_USER_TEMPLATE.format(findings_json=findings_json[:50000])
    return CRITIC_SYSTEM_PROMPT, user


def parse_critic_response(response_data: dict[str, Any]) -> AdversarialCritiqueResult:
    """Parse the LLM response from the adversarial critic."""
    critiques = []
    for item in response_data.get("critiques", []):
        critiques.append(CritiqueItem(
            finding_id=item.get("finding_id", ""),
            critique_type=item.get("critique_type", "unknown"),
            description=item.get("description", ""),
            suggested_action=item.get("suggested_action", ""),
            severity=item.get("severity", "medium"),
        ))
    return AdversarialCritiqueResult(
        findings_reviewed=len(response_data.get("critiques", [])),
        critiques=critiques,
        blind_spots=response_data.get("blind_spots", []),
        assumptions_challenged=response_data.get("assumptions_challenged", []),
        overall_assessment=response_data.get("overall_assessment", ""),
    )


__all__ = [
    "AdversarialCritiqueResult",
    "CRITIC_SYSTEM_PROMPT",
    "CRITIC_USER_TEMPLATE",
    "CritiqueItem",
    "build_critic_prompt",
    "parse_critic_response",
]