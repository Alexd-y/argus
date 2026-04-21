"""``remediation.advisor`` MCP prompt."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from mcp.server.fastmcp.prompts.base import AssistantMessage, UserMessage

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)


_SYSTEM_GUIDANCE = (
    "You are an ARGUS remediation advisor. Propose safe-by-default "
    "remediation steps for the supplied finding. Prefer framework / library "
    "level fixes over custom code. Always include: (a) the smallest change "
    "that fully closes the vulnerability, (b) one defense-in-depth step, and "
    "(c) at least one verification step (test or scanner check) the engineer "
    "can run BEFORE deploying. Never recommend disabling security controls. "
    "If the input describes a destructive remediation (e.g. dropping a "
    "production table), refuse and explain why."
)


def register(mcp: "FastMCP") -> None:
    """Bind the ``remediation.advisor`` prompt to ``mcp``."""

    @mcp.prompt(
        name="remediation.advisor",
        title="Propose safe-by-default remediation steps for a finding",
        description=(
            "Generates step-by-step remediation guidance for a finding. "
            "Inputs: title, severity, stack hint (optional), evidence summary."
        ),
    )
    def remediation_advisor(
        title: str,
        severity: str,
        stack: str | None = None,
        evidence_summary: str | None = None,
        cwe: str | None = None,
    ) -> list[UserMessage | AssistantMessage]:
        """Render the remediation prompt."""
        rendered_input = _render_remediation_block(
            title=title,
            severity=severity,
            stack=stack,
            evidence_summary=evidence_summary,
            cwe=cwe,
        )
        return [
            AssistantMessage(content=_SYSTEM_GUIDANCE),
            UserMessage(content=rendered_input),
        ]


def _render_remediation_block(
    *,
    title: str,
    severity: str,
    stack: str | None,
    evidence_summary: str | None,
    cwe: str | None,
) -> str:
    parts: list[str] = ["REMEDIATION REQUEST", "-------------------"]
    parts.append(f"Title: {title.strip()}")
    parts.append(f"Severity: {severity.strip().lower()}")
    if cwe:
        parts.append(f"CWE: {cwe.strip()}")
    if stack:
        parts.append(f"Stack hint: {stack.strip()[:200]}")
    if evidence_summary:
        parts.append("")
        parts.append("Evidence summary:")
        parts.append(evidence_summary.strip()[:4_000])
    parts.append("")
    parts.append(
        "Please produce a numbered list with at least: 1) primary fix, "
        "2) defense-in-depth control, 3) verification step the engineer can "
        "run BEFORE merging the patch."
    )
    return "\n".join(parts)


__all__ = ["register"]
