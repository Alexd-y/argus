"""MCP prompts (Backlog/dev1_md §13).

Three named prompts are exposed:

* ``vulnerability.explainer`` — explains a finding to a non-security audience.
* ``remediation.advisor`` — proposes safe-by-default remediation steps.
* ``severity.normalizer`` — proposes a normalized severity score and
  CVSS-3.1 vector for an unstructured advisory.

Prompts are *templates only* — they never call the live API. The LLM
client renders the prompt locally and decides what tools to invoke next.
"""

from mcp.server.fastmcp import FastMCP

from src.mcp.prompts import (
    remediation_advisor,
    severity_normalizer,
    vulnerability_explainer,
)


def register_all(mcp: FastMCP) -> None:
    """Register every MCP prompt with ``mcp``."""
    vulnerability_explainer.register(mcp)
    remediation_advisor.register(mcp)
    severity_normalizer.register(mcp)


__all__ = [
    "register_all",
    "remediation_advisor",
    "severity_normalizer",
    "vulnerability_explainer",
]
