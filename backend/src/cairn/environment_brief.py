"""Dynamic environment brief for the Cairn agent (port of upstream C-04).

Upstream ships a static ``AGENTS.md`` inside the container. ARGUS assembles the
brief at runtime from the scan's scope / RoE / execution mode / allowed tools and
writes it into the workspace before a task runs, so the agent always sees the real,
current perimeter — never a hardcoded external IP or tool list.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.policy.scope import ScopeEngine


@dataclass(slots=True)
class EnvironmentBrief:
    execution_mode: str
    scope_lines: list[str]
    allowed_tools: list[str]
    forbidden_actions: list[str]
    oob_collector: str | None = None
    knowledge_hint: str | None = None

    def render(self) -> str:
        lines = [
            "# Engagement environment brief",
            "",
            f"Execution mode: {self.execution_mode}",
            "",
            "## Allowed scope (Rules of Engagement)",
        ]
        lines.extend(
            self.scope_lines or ["(no scope configured — treat everything as OUT of scope)"]
        )
        lines += ["", "## Allowed tools"]
        lines.extend(f"- {tool}" for tool in self.allowed_tools) or lines.append("- (none)")
        lines += ["", "## Forbidden"]
        lines.extend(f"- {item}" for item in self.forbidden_actions)
        if self.oob_collector:
            lines += ["", f"## Out-of-band collector\n{self.oob_collector}"]
        if self.knowledge_hint:
            lines += ["", f"## Knowledge base\n{self.knowledge_hint}"]
        lines += [
            "",
            "## Operational rules",
            "- Never act outside the allowed scope above.",
            "- Do not escalate intrusiveness beyond the current execution mode.",
            "- Run long-lived processes under `tmux` and report the session name.",
            "- Every claimed fact must carry evidence (tool output / artifact).",
        ]
        return "\n".join(lines)


_DEFAULT_FORBIDDEN = (
    "destructive actions (data deletion, DoS, availability impact)",
    "targets outside the allowed scope",
    "exfiltration of data beyond what proves a finding",
)


def build_environment_brief(
    *,
    execution_mode: str,
    scope_engine: ScopeEngine,
    allowed_tools: list[str],
    oob_collector: str | None = None,
    knowledge_hint: str | None = None,
    extra_forbidden: list[str] | None = None,
) -> EnvironmentBrief:
    """Assemble the brief from live scope + execution mode + allowed tools."""
    scope_lines = [
        f"- {rule.kind.value}: {rule.pattern}" + (" (DENY)" if rule.deny else "")
        for rule in scope_engine.rules
    ]
    forbidden = list(_DEFAULT_FORBIDDEN) + list(extra_forbidden or [])
    return EnvironmentBrief(
        execution_mode=execution_mode,
        scope_lines=scope_lines,
        allowed_tools=list(allowed_tools),
        forbidden_actions=forbidden,
        oob_collector=oob_collector,
        knowledge_hint=knowledge_hint,
    )


__all__ = ["EnvironmentBrief", "build_environment_brief"]
