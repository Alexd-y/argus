"""Integration between TargetConfig rules of engagement and the ScopeEngine.

Bridges the declarative AuthConfig rules (focus/avoid) with the existing
ScopeEngine so that scan scoping is driven by the YAML config.
"""

from __future__ import annotations

from typing import Any

from src.orchestration.auth_config import ScopeRuleConfig, TargetConfig
from src.policy.scope import ScopeKind, ScopeRule


def target_config_to_scope_rules(config: TargetConfig) -> tuple[list[ScopeRule], list[ScopeRule]]:
    """Convert TargetConfig focus/avoid rules into ScopeEngine-compatible ScopeRules.

    Returns (allow_rules, deny_rules) tuples suitable for constructing
    a ScopeEngine.
    """
    allow_rules: list[ScopeRule] = []
    deny_rules: list[ScopeRule] = []

    for rule in config.rules.focus:
        scope_rule = _convert_rule_config(rule, deny=False)
        if scope_rule is not None:
            allow_rules.append(scope_rule)

    for rule in config.rules.avoid:
        scope_rule = _convert_rule_config(rule, deny=True)
        if scope_rule is not None:
            deny_rules.append(scope_rule)

    return allow_rules, deny_rules


def _convert_rule_config(rule: ScopeRuleConfig, deny: bool) -> ScopeRule | None:
    """Convert a single ScopeRuleConfig to a ScopeRule."""
    kind = _map_rule_type_to_scope_kind(rule.type)
    if kind is None:
        return None

    return ScopeRule(
        kind=kind,
        pattern=rule.value,
        deny=deny,
        note=rule.description,
    )


def _map_rule_type_to_scope_kind(rule_type: str) -> ScopeKind | None:
    """Map AuthConfig rule types to ScopeKind values."""
    mapping = {
        "url_path": ScopeKind.URL,
        "subdomain": ScopeKind.DOMAIN,
        "domain": ScopeKind.DOMAIN,
        "host": ScopeKind.HOST,
        "ip": ScopeKind.IP,
        "cidr": ScopeKind.CIDR,
    }
    return mapping.get(rule_type.lower())


def rules_of_engagement_to_prompt_context(config: TargetConfig) -> str:
    """Generate a prompt injectable context from rules of engagement.

    This produces a concise text block that can be inserted into LLM
    system prompts to steer scan behavior.
    """
    lines: list[str] = []

    if config.description:
        lines.append(f"Target environment: {config.description}")

    if config.rules.focus:
        lines.append("Focus areas:")
        for rule in config.rules.focus:
            lines.append(f"  - {rule.type}: {rule.value} ({rule.description})")

    if config.rules.avoid:
        lines.append("Avoid areas:")
        for rule in config.rules.avoid:
            lines.append(f"  - {rule.type}: {rule.value} ({rule.description})")

    if config.rules.max_rps:
        lines.append(f"Max requests/second: {config.rules.max_rps}")

    if config.rules.max_concurrent:
        lines.append(f"Max concurrent agents: {config.rules.max_concurrent}")

    if config.rules.rules_text:
        lines.append(f"Rules of engagement: {config.rules.rules_text}")

    if config.vuln_classes:
        lines.append(f"Active vulnerability classes: {', '.join(config.vuln_classes)}")

    lines.append(f"Exploitation phase: {'enabled' if config.exploit else 'disabled'}")

    return "\n".join(lines)


__all__ = [
    "rules_of_engagement_to_prompt_context",
    "target_config_to_scope_rules",
]