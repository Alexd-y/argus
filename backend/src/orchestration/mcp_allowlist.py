"""MCP tool allowlisting per phase — enforced tool access control.

Ensures each scan phase and vuln-agent can only call the MCP tools
that are appropriate for that context. Prevents recon agents from
calling sqlmap, exploitation agents from running nmap, etc.

Ось D (implicit) from Развитие2.md: MCP tool access control.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

PHASE_TOOL_ALLOWLIST: dict[str, set[str]] = {
    "source_analysis": {"git_clone", "tree_sitter_parse", "file_read"},
    "recon": {"nmap", "nuclei", "ffuf", "subfinder", "httpx", "whatweb", "dnsx", "crtsh", "shodan", "amass", "gowitness"},
    "threat_modeling": set(),
    "vuln_analysis": {"nuclei", "dalfox", "ffuf", "nikto", "sqlmap_detect", "wpscan", "dirsearch"},
    "exploitation": {"sqlmap", "commix", "xsstrike", "ssrfmap", "hydra", "john", "hashcat", "browser_navigate", "browser_click", "browser_type", "browser_screenshot", "browser_intercept"},
    "post_exploitation": {"linpeas", "winpeas", "ldapsearch", "enum4linux", "crackmapexec", "browser_navigate"},
    "reporting": set(),
}

VULN_DOMAIN_TOOL_ALLOWLIST: dict[str, set[str]] = {
    "injection": {"sqlmap", "commix", "nosqlmap", "sqlmap_detect"},
    "xss": {"dalfox", "xsstrike", "browser_navigate", "browser_screenshot"},
    "auth": {"hydra", "john", "hashcat", "browser_navigate", "browser_type", "browser_click"},
    "authz": {"burp_suite", "authmatrix"},
    "ssrf": {"ssrfmap", "gf_ssrf"},
}


@dataclass
class ToolAccessDenied:
    tool_name: str
    phase: str
    reason: str


class MCPAllowlist:
    def get_allowed_tools(self, phase: str, vuln_domain: str | None = None) -> set[str]:
        phase_tools = PHASE_TOOL_ALLOWLIST.get(phase, set())
        domain_tools: set[str] = set()
        if vuln_domain:
            domain_tools = VULN_DOMAIN_TOOL_ALLOWLIST.get(vuln_domain, set())
        return phase_tools | domain_tools

    def guard_tool_call(self, tool_name: str, phase: str, vuln_domain: str | None = None) -> ToolAccessDenied | None:
        allowed = self.get_allowed_tools(phase, vuln_domain)
        if not allowed:
            return None
        if tool_name not in allowed:
            return ToolAccessDenied(
                tool_name=tool_name,
                phase=phase,
                reason=f"Tool '{tool_name}' not allowed in phase '{phase}' (domain={vuln_domain})",
            )
        return None


__all__ = [
    "MCPAllowlist",
    "PHASE_TOOL_ALLOWLIST",
    "VULN_DOMAIN_TOOL_ALLOWLIST",
    "ToolAccessDenied",
]