"""LLM Policy Models — strict Pydantic contracts for per-scan/per-tenant LLM routing.

Defines: compliance flags, budget caps, per-role routing config, OSINT enablement,
safety telemetry, and profile defaults (quick/standard/deep/enterprise).

Stored as `policy_jsonb` per-scan, passed to llm-gateway on each call.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, model_validator


class Profile(str, Enum):
    QUICK = "quick"
    STANDARD = "standard"
    DEEP = "deep"
    ENTERPRISE = "enterprise"


class LogMode(str, Enum):
    FULL = "full"
    HASHED = "hashed"
    SUMMARY_ONLY = "summary_only"
    OFF = "off"


# ===== Compliance =====

class Compliance(BaseModel):
    no_third_party_osint: bool = False
    no_cloud_llm_for_source_code: bool = False
    airgapped_only: bool = False


# ===== Budget =====

class Budget(BaseModel):
    max_cost_usd: float = Field(default=0.5, gt=0.0)
    soft_limit_usd: float = Field(default=0.4, gt=0.0)
    max_input_tokens: int = Field(default=400000, gt=0)
    max_output_tokens: int = Field(default=100000, gt=0)


# ===== Per-role route config =====

class RouteConfig(BaseModel):
    preferred_aliases: list[str] = Field(default_factory=list)
    fallback_aliases: list[str] = Field(default_factory=list)
    local_only: bool = False
    max_calls: int = Field(default=20, gt=0)
    max_input_tokens: int = Field(default=200000, gt=0)
    max_output_tokens: int = Field(default=50000, gt=0)
    max_cost_usd: float = Field(default=0.15, gt=0.0)


class Routing(BaseModel):
    pentest: RouteConfig = Field(default_factory=lambda: RouteConfig(
        preferred_aliases=["argus-pentest-primary"],
        fallback_aliases=[],
        max_calls=50,
    ))
    planner: RouteConfig = Field(default_factory=lambda: RouteConfig(
        preferred_aliases=["argus-pentest-primary"],
        fallback_aliases=["argus-planner-fast", "argus-planner-deep"],
    ))
    code: RouteConfig = Field(default_factory=lambda: RouteConfig(
        preferred_aliases=["argus-pentest-primary"],
        fallback_aliases=["argus-code-cloud"],
    ))
    devsecops: RouteConfig = Field(default_factory=lambda: RouteConfig(
        preferred_aliases=["argus-pentest-primary"],
        fallback_aliases=[],
        local_only=True,
    ))
    report: RouteConfig = Field(default_factory=lambda: RouteConfig(
        preferred_aliases=["argus-pentest-primary"],
        fallback_aliases=["argus-report"],
    ))


# ===== OSINT =====

class OSINTConfig(BaseModel):
    alias: str = "argus-osint"
    enabled: bool = True
    max_requests: int = Field(default=5, gt=0)
    max_cost_usd: float = Field(default=0.1, gt=0.0)


# ===== Safety / Scope =====

class Scope(BaseModel):
    domains: list[str] = Field(default_factory=list)
    cidrs: list[str] = Field(default_factory=list)
    allow_prod: bool = False


class Safety(BaseModel):
    allow_offensive_security: bool = True
    pentest_scope: Scope = Field(default_factory=Scope)


# ===== Telemetry =====

class Telemetry(BaseModel):
    trace_id: str = ""
    log_prompts: LogMode = LogMode.HASHED
    log_responses: LogMode = LogMode.SUMMARY_ONLY


# ===== Full Policy =====

class LLMPolicy(BaseModel):
    tenant_id: str = ""
    scan_id: str = ""
    profile: Profile = Profile.STANDARD
    region: str = "eu-central-1"
    compliance: Compliance = Field(default_factory=Compliance)
    budget: Budget = Field(default_factory=Budget)
    routing: Routing = Field(default_factory=Routing)
    osint: OSINTConfig = Field(default_factory=OSINTConfig)
    safety: Safety = Field(default_factory=Safety)
    telemetry: Telemetry = Field(default_factory=Telemetry)

    @model_validator(mode="after")
    def validate_constraints(self) -> LLMPolicy:
        if self.budget.soft_limit_usd >= self.budget.max_cost_usd:
            raise ValueError("soft_limit_usd must be less than max_cost_usd")
        for role_name, route in self.routing.model_dump().items():
            if isinstance(route, dict):
                if route.get("local_only"):
                    for alias in route.get("preferred_aliases", []):
                        if alias not in ("argus-pentest-primary", "argus-code-local", "argus-devsecops-local"):
                            raise ValueError(
                                f"Route {role_name} has local_only=True but alias {alias} may be cloud"
                            )
        return self


# ===== Profile defaults =====

PROFILE_DEFAULTS: dict[Profile, dict[str, Any]] = {
    Profile.QUICK: {
        "budget": {"max_cost_usd": 0.15, "soft_limit_usd": 0.12, "max_input_tokens": 100000, "max_output_tokens": 25000},
        "routing": {
            "planner": {"max_calls": 3, "max_input_tokens": 50000, "max_cost_usd": 0.05},
            "code": {"max_calls": 5, "max_input_tokens": 50000, "max_cost_usd": 0.05},
            "report": {"max_calls": 1, "max_input_tokens": 20000, "max_cost_usd": 0.05},
        },
    },
    Profile.STANDARD: {
        "budget": {"max_cost_usd": 0.50, "soft_limit_usd": 0.40, "max_input_tokens": 400000, "max_output_tokens": 100000},
        "routing": {
            "planner": {"max_calls": 10, "max_input_tokens": 200000, "max_cost_usd": 0.15},
            "code": {"max_calls": 15, "max_input_tokens": 150000, "max_cost_usd": 0.15},
            "report": {"max_calls": 3, "max_input_tokens": 50000, "max_cost_usd": 0.10},
        },
    },
    Profile.DEEP: {
        "budget": {"max_cost_usd": 1.50, "soft_limit_usd": 1.20, "max_input_tokens": 800000, "max_output_tokens": 200000},
        "routing": {
            "planner": {"max_calls": 25, "max_input_tokens": 400000, "max_cost_usd": 0.40},
            "code": {"max_calls": 30, "max_input_tokens": 300000, "max_cost_usd": 0.35},
            "report": {"max_calls": 5, "max_input_tokens": 80000, "max_cost_usd": 0.20},
        },
    },
    Profile.ENTERPRISE: {
        "budget": {"max_cost_usd": 5.00, "soft_limit_usd": 4.00, "max_input_tokens": 2000000, "max_output_tokens": 500000},
        "routing": {
            "planner": {"max_calls": 50, "max_input_tokens": 800000, "max_cost_usd": 1.00},
            "code": {"max_calls": 60, "max_input_tokens": 600000, "max_cost_usd": 0.80},
            "report": {"max_calls": 10, "max_input_tokens": 150000, "max_cost_usd": 0.40},
        },
    },
}


def build_effective_policy(
    *,
    tenant_id: str = "",
    scan_id: str = "",
    profile: Profile = Profile.STANDARD,
    compliance_overrides: dict[str, Any] | None = None,
    budget_overrides: dict[str, Any] | None = None,
    routing_overrides: dict[str, Any] | None = None,
) -> LLMPolicy:
    defaults = PROFILE_DEFAULTS.get(profile, PROFILE_DEFAULTS[Profile.STANDARD])

    budget_data = {**defaults["budget"], **(budget_overrides or {})}
    routing_data = defaults["routing"]

    routing = Routing(
        planner=RouteConfig(**(routing_data.get("planner", {}))),
        code=RouteConfig(**(routing_data.get("code", {}))),
        report=RouteConfig(**(routing_data.get("report", {}))),
    )

    compliance = Compliance(**(compliance_overrides or {}))

    if routing_overrides:
        for role_name, overrides in routing_overrides.items():
            existing = getattr(routing, role_name, None)
            if existing:
                for k, v in overrides.items():
                    setattr(existing, k, v)

    return LLMPolicy(
        tenant_id=tenant_id,
        scan_id=scan_id,
        profile=profile,
        budget=Budget(**budget_data),
        routing=routing,
        compliance=compliance,
    )
