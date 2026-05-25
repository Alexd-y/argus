"""AI/ML security vertical — prompt-injection scanner + MCP supply-chain analysis.

Specialized scanner for AI/ML attack surfaces: prompt injection in
LLM integrations, MCP tool supply-chain risks, training data leak detection.

Ось C / Фаза 3 из Развитие2.md: AI/ML vertical.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


PROMPT_INJECTION_PATTERNS = [
    (r"ignore\s+(previous|all|above)\s+instructions?", "direct_instruction_override"),
    (r"system\s*:\s*you\s+are", "system_role_injection"),
    (r"<\|im_start\|>", "tokenizer_boundary_injection"),
    (r"extract\s+(the|your)\s+(system|initial)\s*prompt", "prompt_extraction"),
    (r"jailbreak", "jailbreak_keyword"),
    (r"DAN\s+mode", "persona_hijack"),
    (r"developer\s+mode", "developer_mode_bypass"),
]


@dataclass
class PromptInjectionFinding:
    """A prompt injection vulnerability found by the scanner."""

    finding_type: str
    severity: str
    input_field: str
    pattern_matched: str
    description: str
    recommendation: str


@dataclass
class MCPSupplyChainRisk:
    """A supply-chain risk in an MCP tool integration."""

    tool_name: str
    risk_type: str
    severity: str
    description: str


@dataclass
class AIMLSecurityScanResult:
    """Result of an AI/ML security scan."""

    prompt_injection_findings: list[PromptInjectionFinding] = field(default_factory=list)
    mcp_supply_chain_risks: list[MCPSupplyChainRisk] = field(default_factory=list)
    training_data_leaks: list[str] = field(default_factory=list)
    overall_risk: str = "low"


class AIMLSecurityScanner:
    """Scanner for AI/ML attack surfaces."""

    def scan_prompt_inputs(
        self,
        inputs: dict[str, str],
        context: str = "",
    ) -> list[PromptInjectionFinding]:
        findings: list[PromptInjectionFinding] = []
        for field_name, value in inputs.items():
            for pattern, attack_type in PROMPT_INJECTION_PATTERNS:
                if re.search(pattern, value, re.IGNORECASE):
                    findings.append(PromptInjectionFinding(
                        finding_type=attack_type,
                        severity="high",
                        input_field=field_name,
                        pattern_matched=pattern,
                        description=f"Prompt injection pattern '{attack_type}' detected in '{field_name}'",
                        recommendation=f"Wrap '{field_name}' in <untrusted_input> tags and add instruction hierarchy",
                    ))
        return findings

    def scan_mcp_tools(
        self,
        tools: list[dict[str, Any]],
    ) -> list[MCPSupplyChainRisk]:
        risks: list[MCPSupplyChainRisk] = []
        for tool in tools:
            name = tool.get("name", "unknown")
            endpoint = tool.get("backend_endpoint", "")
            if not endpoint:
                risks.append(MCPSupplyChainRisk(
                    tool_name=name,
                    risk_type="no_endpoint_validation",
                    severity="medium",
                    description=f"Tool '{name}' has no backend endpoint validation",
                ))
            args = tool.get("args_schema", [])
            for arg in args:
                if not arg.get("validation", ""):
                    pass
        return risks

    def scan_training_data_leaks(
        self,
        responses: list[str],
        patterns: list[str] | None = None,
    ) -> list[str]:
        leak_patterns = patterns or [
            r"API[_-]?KEY\s*[:=]\s*['\"]?\w{20,}",
            r"password\s*[:=]\s*['\"]?\w{8,}",
            r"secret\s*[:=]\s*['\"]?\w{16,}",
        ]
        leaks: list[str] = []
        for response in responses:
            for pattern in leak_patterns:
                if re.search(pattern, response, re.IGNORECASE):
                    leaks.append(f"Potential data leak pattern matched: {pattern}")
        return leaks


__all__ = [
    "AIMLSecurityScanner",
    "AIMLSecurityScanResult",
    "MCPSupplyChainRisk",
    "PROMPT_INJECTION_PATTERNS",
    "PromptInjectionFinding",
]