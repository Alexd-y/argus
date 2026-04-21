"""``severity.normalizer`` MCP prompt."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from mcp.server.fastmcp.prompts.base import AssistantMessage, UserMessage

if TYPE_CHECKING:  # pragma: no cover
    from mcp.server.fastmcp import FastMCP

_logger = logging.getLogger(__name__)


_SYSTEM_GUIDANCE = (
    "You are an ARGUS severity normalizer. Given a free-form vulnerability "
    "advisory, propose: (a) one of CRITICAL / HIGH / MEDIUM / LOW / INFO, "
    "(b) a CVSS-3.1 vector AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_, and (c) the "
    "OWASP 2025 Top-10 short id (A01..A10) that best matches. Stay strictly "
    "within these enumerations. If the input is ambiguous, propose the "
    "lower of two candidate ratings and explain in one sentence why the "
    "evidence does not support a higher rating."
)


def register(mcp: "FastMCP") -> None:
    """Bind the ``severity.normalizer`` prompt to ``mcp``."""

    @mcp.prompt(
        name="severity.normalizer",
        title="Normalize advisory severity to CVSS-3.1 + OWASP Top-10",
        description=(
            "Maps an unstructured advisory to ARGUS-canonical severity, "
            "CVSS-3.1 vector, and OWASP 2025 Top-10 category."
        ),
    )
    def severity_normalizer(
        advisory_text: str,
        impact_hint: str | None = None,
    ) -> list[UserMessage | AssistantMessage]:
        """Render the severity-normalizer prompt."""
        rendered_input = _render_advisory_block(
            advisory_text=advisory_text,
            impact_hint=impact_hint,
        )
        return [
            AssistantMessage(content=_SYSTEM_GUIDANCE),
            UserMessage(content=rendered_input),
        ]


def _render_advisory_block(
    *,
    advisory_text: str,
    impact_hint: str | None,
) -> str:
    parts: list[str] = ["ADVISORY", "--------"]
    parts.append(advisory_text.strip()[:8_000])
    if impact_hint:
        parts.append("")
        parts.append(f"Operator impact hint: {impact_hint.strip()[:500]}")
    parts.append("")
    parts.append(
        "Please respond with three labelled lines:"
        "\nseverity: <CRITICAL|HIGH|MEDIUM|LOW|INFO>"
        "\ncvss: <CVSS:3.1/AV:.../I:.../A:...>"
        "\nowasp: <A01..A10>"
        "\nfollowed by ONE explanatory sentence."
    )
    return "\n".join(parts)


__all__ = ["register"]
