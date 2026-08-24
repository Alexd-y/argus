"""CWE-specialized vulnerability analysis agents.

Implements 5 parallel CWE-specific analysis agents inspired by Shannon's
parallel vuln-exploit agent pairs. Each agent focuses on one OWASP
attack domain with specialized prompts, tool allowlists, and context.

This module provides the fan-out definition for the Celery task system.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from src.orchestration.exploitation_queue import VulnClass


class AgentDomain(StrEnum):
    """Vulnerability analysis domains matching Shannon's 5 attack categories."""

    INJECTION = "injection"
    XSS = "xss"
    AUTH = "auth"
    AUTHZ = "authz"
    SSRF = "ssrf"


@dataclass(frozen=True)
class VulnAgentSpec:
    """Specification for a CWE-specialized vulnerability analysis agent."""

    domain: AgentDomain
    vuln_class: VulnClass
    display_name: str
    prompt_key: str
    tool_allowlist: tuple[str, ...]
    cwe_focus: tuple[int, ...]
    description: str


VULN_AGENT_SPECS: dict[AgentDomain, VulnAgentSpec] = {
    AgentDomain.INJECTION: VulnAgentSpec(
        domain=AgentDomain.INJECTION,
        vuln_class=VulnClass.INJECTION,
        display_name="Injection Analyst",
        prompt_key="vuln-injection",
        tool_allowlist=(
            "sqlmap", "commix", "ffuf", "gobuster", "wfuzz",
            "httpx", "curl", "nuclei",
        ),
        cwe_focus=(89, 78, 77, 564, 917, 94, 943, 639),
        description=(
            "Detects SQL injection (CWE-89), OS command injection (CWE-78), "
            "code injection (CWE-94), LDAP injection (CWE-90), XSS via template "
            "injection (CWE-77). Uses sqlmap, commix, ffuf for payload testing. "
            "Performs source-to-sink taint analysis for user input reaching "
            "dangerous query/exec functions."
        ),
    ),
    AgentDomain.XSS: VulnAgentSpec(
        domain=AgentDomain.XSS,
        vuln_class=VulnClass.XSS,
        display_name="XSS Analyst",
        prompt_key="vuln-xss",
        tool_allowlist=(
            "dalfox", "xsstrike", "nuclei", "httpx",
            "curl", "browser_navigate", "browser_execute_js", "browser_screenshot",
        ),
        cwe_focus=(79, 80, 81, 83, 87, 692, 1021),
        description=(
            "Detects reflected XSS (CWE-79), stored XSS (CWE-80), DOM XSS (CWE-79), "
            "mutation XSS (CWE-692). Uses dalfox, xsstrike for automated payload "
            "testing and Playwright browser automation for PoC confirmation "
            "(alert/prompt/confirm dialogs). Checks Content-Security-Policy headers."
        ),
    ),
    AgentDomain.AUTH: VulnAgentSpec(
        domain=AgentDomain.AUTH,
        vuln_class=VulnClass.AUTH,
        display_name="Auth Analyst",
        prompt_key="vuln-auth",
        tool_allowlist=(
            "hydra", "medusa", "nuclei", "httpx",
            "curl", "browser_navigate", "browser_login",
        ),
        cwe_focus=(287, 290, 294, 308, 307, 521, 640, 255, 256, 259),
        description=(
            "Detects broken authentication: default credentials (CWE-521), "
            "weak passwords (CWE-290), missing MFA (CWE-308), credential "
            "stuffing vectors (CWE-307), session fixation (CWE-287). "
            "Uses hydra/medusa for password audit, browser_login for auth flow testing."
        ),
    ),
    AgentDomain.AUTHZ: VulnAgentSpec(
        domain=AgentDomain.AUTHZ,
        vuln_class=VulnClass.AUTHZ,
        display_name="Authz Analyst",
        prompt_key="vuln-authz",
        tool_allowlist=(
            "ffuf", "gobuster", "nuclei", "httpx",
            "curl", "browser_navigate", "browser_click",
        ),
        cwe_focus=(862, 863, 284, 639, 285, 648, 918),
        description=(
            "Detects broken access control: IDOR (CWE-639), privilege "
            "escalation (CWE-863), missing auth checks (CWE-862), directory "
            "traversal (CWE-284), mass assignment (CWE-915). Tests multiple "
            "user roles and privilege boundaries."
        ),
    ),
    AgentDomain.SSRF: VulnAgentSpec(
        domain=AgentDomain.SSRF,
        vuln_class=VulnClass.SSRF,
        display_name="SSRF Analyst",
        prompt_key="vuln-ssrf",
        tool_allowlist=(
            "nuclei", "httpx", "curl", "ffuf",
            "browser_navigate", "browser_execute_js",
        ),
        cwe_focus=(918, 922, 441, 406, 236, 384),
        description=(
            "Detects SSRF (CWE-918): internal network access via URL parameters, "
            "cloud metadata endpoint access (169.254.169.254), DNS rebinding, "
            "open redirect chaining. Tests for IMDS/AWS/GCP/Azure metadata "
            "endpoint exposure. Checks for URL validation bypass via encoding, "
            "IPv6, and domain fronting."
        ),
    ),
}

ALL_AGENT_DOMAINS: list[AgentDomain] = list(AgentDomain)
ALL_VULN_CLASSES: list[VulnClass] = list(VulnClass)


def get_agent_spec(domain: AgentDomain) -> VulnAgentSpec:
    """Get the agent specification for a given domain."""
    return VULN_AGENT_SPECS[domain]


def get_tools_for_domain(domain: AgentDomain) -> tuple[str, ...]:
    """Get the tool allowlist for a given agent domain."""
    return VULN_AGENT_SPECS[domain].tool_allowlist


def get_cwe_focus_for_domain(domain: AgentDomain) -> tuple[int, ...]:
    """Get the CWE focus list for a given agent domain."""
    return VULN_AGENT_SPECS[domain].cwe_focus


def filter_findings_by_domain(
    findings: list[dict[str, Any]],
    domain: AgentDomain,
) -> list[dict[str, Any]]:
    """Filter findings relevant to a specific agent domain based on CWE."""
    cwe_set = set(VULN_AGENT_SPECS[domain].cwe_focus)
    relevant: list[dict[str, Any]] = []
    for f in findings:
        finding_cwes = f.get("cwe", [])
        if isinstance(finding_cwes, int):
            finding_cwes = [finding_cwes]
        if isinstance(finding_cwes, list):
            for cwe_val in finding_cwes:
                try:
                    if int(cwe_val) in cwe_set:
                        relevant.append(f)
                        break
                except (ValueError, TypeError):
                    pass

        category = str(f.get("category", "")).lower()
        domain_lower = domain.value.lower()
        if domain_lower in category or category in domain_lower:
            if f not in relevant:
                relevant.append(f)

    return relevant


def build_agent_tasks(
    target: str,
    findings: list[dict[str, Any]],
    scan_id: str = "",
    tenant_id: str = "",
) -> list[dict[str, Any]]:
    """Build per-domain agent task descriptors for Celery fan-out.

    Returns a list of task descriptors, one per domain that has
    relevant findings. Each descriptor contains the agent spec,
    filtered findings, and execution context.

    The caller (state_machine or Celery chord) dispatches these
    as parallel tasks and collects results.
    """
    tasks: list[dict[str, Any]] = []
    for domain in ALL_AGENT_DOMAINS:
        spec = VULN_AGENT_SPECS[domain]
        relevant = filter_findings_by_domain(findings, domain)
        if not relevant:
            continue
        tasks.append({
            "domain": domain.value,
            "display_name": spec.display_name,
            "prompt_key": spec.prompt_key,
            "tool_allowlist": list(spec.tool_allowlist),
            "cwe_focus": list(spec.cwe_focus),
            "findings": relevant,
            "target": target,
            "scan_id": scan_id,
            "tenant_id": tenant_id,
        })
    return tasks


__all__ = [
    "ALL_AGENT_DOMAINS",
    "ALL_VULN_CLASSES",
    "AgentDomain",
    "VULN_AGENT_SPECS",
    "VulnAgentSpec",
    "filter_findings_by_domain",
    "get_agent_spec",
    "get_cwe_focus_for_domain",
    "get_tools_for_domain",
]
