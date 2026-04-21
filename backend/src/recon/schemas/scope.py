"""Scope definition and validation schemas."""

from pydantic import BaseModel, field_validator


class ScopeRule(BaseModel):
    """Single scope rule — include or exclude a pattern."""
    rule_type: str = "include"  # include / exclude
    value_type: str = "domain"  # domain / ip / cidr / regex
    pattern: str

    @field_validator("rule_type")
    @classmethod
    def validate_rule_type(cls, v: str) -> str:
        if v not in ("include", "exclude"):
            raise ValueError("rule_type must be 'include' or 'exclude'")
        return v

    @field_validator("value_type")
    @classmethod
    def validate_value_type(cls, v: str) -> str:
        if v not in ("domain", "ip", "cidr", "regex"):
            raise ValueError("value_type must be one of: domain, ip, cidr, regex")
        return v

    @field_validator("pattern")
    @classmethod
    def validate_pattern_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("pattern cannot be empty")
        return v.strip()


class ScopeConfig(BaseModel):
    """Full engagement scope configuration."""
    rules: list[ScopeRule] = []
    wildcard_subdomains: bool = True
    allowed_scan_types: list[str] = []
    roe_text: str = ""
    max_rate_per_second: int = 10
    notes: str = ""

    @field_validator("rules")
    @classmethod
    def validate_rules(cls, v: list[ScopeRule]) -> list[ScopeRule]:
        include_count = sum(1 for r in v if r.rule_type == "include")
        if v and include_count == 0:
            raise ValueError("At least one 'include' rule is required when rules are specified")
        return v


class ScopeValidationResult(BaseModel):
    """Result of a scope validation check."""
    is_in_scope: bool
    matched_rule: ScopeRule | None = None
    reason: str = ""
