"""Command parser — extract tool name and target from command string for /execute guardrails."""

import shlex

# Allowlist for POST /tools/execute — only these tools may be executed
ALLOWED_TOOLS = frozenset({
    "nmap", "nuclei", "nikto", "gobuster", "sqlmap", "dig", "whois", "host", "curl",
    "gitleaks", "trivy", "semgrep", "trufflehog", "prowler", "scout", "checkov", "terrascan",
    "searchsploit",
})

# Tool -> (flag, tool_name for validate_target_for_tool)
_TOOL_TARGET_PATTERNS: dict[str, tuple[str, str]] = {
    "nuclei": ("-u", "nuclei"),
    "nikto": ("-h", "nikto"),
    "gobuster": ("-u", "gobuster"),
    "sqlmap": ("-u", "sqlmap"),
}

_FIRST_POSITIONAL_TARGET_TOOLS = frozenset({"nmap", "dig", "whois"})


def extract_tool_name(command: str) -> str | None:
    """Extract first token (tool name) from command. Returns None if empty/invalid."""
    parts = shlex.split(command)
    if not parts:
        return None
    return parts[0].lower()


def extract_target_from_command(command: str, tool_name: str) -> str | None:
    """
    Extract target/host from command for known tools.
    Returns target string or None if not found/not applicable.
    """
    parts = shlex.split(command)
    if len(parts) < 2:
        return None

    if tool_name in _TOOL_TARGET_PATTERNS:
        flag, _ = _TOOL_TARGET_PATTERNS[tool_name]
        try:
            idx = parts.index(flag)
            if idx + 1 < len(parts):
                return parts[idx + 1]
        except ValueError:
            pass
        return None

    if tool_name in _FIRST_POSITIONAL_TARGET_TOOLS:
        for arg in parts[1:]:
            if not arg.startswith("-"):
                return arg
        return None

    return None


def parse_execute_command(command: str) -> tuple[str | None, str | None]:
    """
    Parse command for /execute endpoint.
    Returns (tool_name, target) or (None, None) if invalid.
    """
    tool = extract_tool_name(command)
    if not tool or tool not in ALLOWED_TOOLS:
        return None, None
    target = extract_target_from_command(command, tool)
    return tool, target
