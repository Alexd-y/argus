"""Resolve a tenant request into a frozen :class:`QuickScanConfig`.

Feature-flag checks belong to the API layer (QUICK-007). This resolver
works even when ``quick_mode_enabled`` is false.

Unknown profile names raise :class:`UnknownQuickProfileError` with
``code = unknown_quick_profile`` (HTTP 400 at the API boundary).
"""

from __future__ import annotations

import logging

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr

from src.quick.profiles import (
    DeploymentQuickClamps,
    QuickProfileCatalog,
    QuickProfileDefaults,
    TenantQuickLimits,
    clamp_int,
    default_clamps,
    load_quick_profiles,
)
from src.quick.schemas import QuickProfileName, QuickScanConfig, SeverityFloor

logger = logging.getLogger(__name__)


class UnknownQuickProfileError(ValueError):
    """Unknown profile. API maps this to HTTP 400 ``unknown_quick_profile``."""

    code = "unknown_quick_profile"

    def __init__(self, profile: str) -> None:
        self.profile = profile
        super().__init__(f"unknown_quick_profile:{profile}")


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class QuickProfileRequest(_Frozen):
    """Caller-supplied Quick options. Extra fields are rejected."""

    profile: StrictStr
    wall_clock_budget_seconds: StrictInt | None = Field(default=None, ge=1, le=86_400)
    ai_budget_seconds: StrictInt | None = Field(default=None, ge=0, le=86_400)
    reserve_for_validation_percent: StrictInt | None = Field(default=None, ge=0, le=50)
    max_targets: StrictInt | None = Field(default=None, ge=1, le=10_000)
    max_urls_per_host: StrictInt | None = Field(default=None, ge=1, le=10_000)
    crawl_depth: StrictInt | None = Field(default=None, ge=0, le=10)
    severity_floor: SeverityFloor | None = None
    enable_ai: StrictBool | None = None
    enable_oast: StrictBool | None = None
    enable_headless_on_signal: StrictBool | None = None
    authenticated_context_id: StrictStr | None = Field(default=None, max_length=36)
    template_policy_id: StrictStr | None = Field(default=None, min_length=1, max_length=128)
    cloud_llm_allowed: StrictBool | None = None


def parse_quick_profile_name(raw: str | QuickProfileName) -> QuickProfileName:
    if isinstance(raw, QuickProfileName):
        return raw
    normalized = str(raw).strip().lower()
    try:
        return QuickProfileName(normalized)
    except ValueError as exc:
        raise UnknownQuickProfileError(normalized) from exc


def _as_request(requested: QuickProfileRequest | str | QuickProfileName) -> QuickProfileRequest:
    if isinstance(requested, QuickProfileRequest):
        return requested
    return QuickProfileRequest(profile=str(requested))


def _as_tenant(tenant: TenantQuickLimits | str) -> TenantQuickLimits:
    if isinstance(tenant, TenantQuickLimits):
        return tenant
    return TenantQuickLimits(tenant_id=str(tenant).strip())


def _pick_int(requested: int | None, default: int, cap: int, lo: int) -> int:
    value = default if requested is None else requested
    return clamp_int(value, lo=lo, hi=cap)


def _resolve_cloud_llm_allowed(
    requested: bool | None,
    yaml_default: bool,
    tenant: TenantQuickLimits,
    clamps: DeploymentQuickClamps,
) -> bool:
    # Fail-closed: every layer must allow it. YAML/deployment/tenant default false.
    wanted = yaml_default if requested is None else requested
    return bool(wanted and yaml_default and tenant.cloud_llm_allowed and clamps.cloud_llm_allowed)


class QuickProfileResolver:
    """``resolve(tenant, requested) → frozen QuickScanConfig``."""

    def __init__(
        self,
        catalog: QuickProfileCatalog | None = None,
        clamps: DeploymentQuickClamps | None = None,
    ) -> None:
        self._catalog = catalog if catalog is not None else load_quick_profiles()
        self._clamps = clamps if clamps is not None else default_clamps()

    def resolve(
        self,
        tenant: TenantQuickLimits | str,
        requested: QuickProfileRequest | str | QuickProfileName,
    ) -> QuickScanConfig:
        tenant_limits = _as_tenant(tenant)
        request = _as_request(requested)
        profile = parse_quick_profile_name(request.profile)
        defaults = self._catalog.get(profile)
        config = self._build_config(profile, defaults, request, tenant_limits)
        logger.info(
            "quick_profile_resolved",
            extra={
                "tenant_id": tenant_limits.tenant_id,
                "profile": config.profile.value,
                "wall_clock_budget_seconds": config.wall_clock_budget_seconds,
                "ai_budget_seconds": config.ai_budget_seconds,
                "cloud_llm_allowed": config.cloud_llm_allowed,
            },
        )
        return config

    def _build_config(
        self,
        profile: QuickProfileName,
        defaults: QuickProfileDefaults,
        request: QuickProfileRequest,
        tenant: TenantQuickLimits,
    ) -> QuickScanConfig:
        wall_cap = self._clamps.wall_clock_cap_for(profile, defaults.wall_clock_budget_seconds)
        if tenant.max_wall_clock_budget_seconds is not None:
            wall_cap = min(wall_cap, tenant.max_wall_clock_budget_seconds)
        wall_clock = _pick_int(
            request.wall_clock_budget_seconds,
            defaults.wall_clock_budget_seconds,
            wall_cap,
            lo=1,
        )

        ai_cap = defaults.ai_budget_seconds
        if tenant.max_ai_budget_seconds is not None:
            ai_cap = min(ai_cap, tenant.max_ai_budget_seconds)
        ai_budget = _pick_int(request.ai_budget_seconds, defaults.ai_budget_seconds, ai_cap, lo=0)
        ai_budget = min(ai_budget, wall_clock)

        reserve_cap = 50
        reserve = _pick_int(
            request.reserve_for_validation_percent,
            defaults.reserve_for_validation_percent,
            reserve_cap,
            lo=0,
        )

        targets_cap = defaults.max_targets
        if tenant.max_targets is not None:
            targets_cap = min(targets_cap, tenant.max_targets)
        max_targets = _pick_int(request.max_targets, defaults.max_targets, targets_cap, lo=1)

        urls_cap = defaults.max_urls_per_host
        if tenant.max_urls_per_host is not None:
            urls_cap = min(urls_cap, tenant.max_urls_per_host)
        max_urls = _pick_int(
            request.max_urls_per_host,
            defaults.max_urls_per_host,
            urls_cap,
            lo=1,
        )

        depth_cap = defaults.crawl_depth
        if tenant.max_crawl_depth is not None:
            depth_cap = min(depth_cap, tenant.max_crawl_depth)
        crawl_depth = _pick_int(request.crawl_depth, defaults.crawl_depth, depth_cap, lo=0)

        template_policy_id = request.template_policy_id or defaults.template_policy_id
        return QuickScanConfig(
            profile=profile,
            wall_clock_budget_seconds=wall_clock,
            ai_budget_seconds=ai_budget,
            reserve_for_validation_percent=reserve,
            max_targets=max_targets,
            max_urls_per_host=max_urls,
            crawl_depth=crawl_depth,
            severity_floor=request.severity_floor or defaults.severity_floor,
            enable_ai=defaults.enable_ai if request.enable_ai is None else request.enable_ai,
            enable_oast=defaults.enable_oast if request.enable_oast is None else request.enable_oast,
            enable_headless_on_signal=(
                defaults.enable_headless_on_signal
                if request.enable_headless_on_signal is None
                else request.enable_headless_on_signal
            ),
            authenticated_context_id=request.authenticated_context_id,
            template_policy_id=template_policy_id,
            cloud_llm_allowed=_resolve_cloud_llm_allowed(
                request.cloud_llm_allowed,
                defaults.cloud_llm_allowed,
                tenant,
                self._clamps,
            ),
        )


__all__ = [
    "QuickProfileRequest",
    "QuickProfileResolver",
    "UnknownQuickProfileError",
    "parse_quick_profile_name",
]
