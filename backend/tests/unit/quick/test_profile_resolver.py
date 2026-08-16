"""QUICK-002 — QuickProfileResolver: YAML defaults, clamps, unknown profile."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from src.quick.profiles import (
    DeploymentQuickClamps,
    TenantQuickLimits,
    load_quick_profiles,
)
from src.quick.resolver import (
    QuickProfileRequest,
    QuickProfileResolver,
    UnknownQuickProfileError,
    parse_quick_profile_name,
)
from src.quick.schemas import QuickProfileName, QuickScanConfig, SeverityFloor

_TENANT_ID = "tenant-quick-002-resolver-01"
_CATALOG = load_quick_profiles()


def _clamps(**overrides) -> DeploymentQuickClamps:
    return DeploymentQuickClamps(**overrides)


def _resolver(clamps: DeploymentQuickClamps | None = None) -> QuickProfileResolver:
    return QuickProfileResolver(catalog=_CATALOG, clamps=clamps or _clamps())


def _tenant(**overrides) -> TenantQuickLimits:
    base: dict = {"tenant_id": _TENANT_ID}
    base.update(overrides)
    return TenantQuickLimits(**base)


@pytest.mark.parametrize(
    ("profile", "wall_clock", "ai_budget", "reserve_percent"),
    [
        (QuickProfileName.COMPACT, 300, 30, 15),
        (QuickProfileName.BALANCED, 900, 90, 20),
        (QuickProfileName.EXTENDED, 1800, 180, 25),
        ("compact", 300, 30, 15),
        ("balanced", 900, 90, 20),
        ("extended", 1800, 180, 25),
    ],
)
def test_compact_balanced_extended_wall_clock_defaults(
    profile: QuickProfileName | str,
    wall_clock: int,
    ai_budget: int,
    reserve_percent: int,
) -> None:
    cfg = _resolver().resolve(_TENANT_ID, profile)
    assert cfg.profile is QuickProfileName(str(profile))
    assert cfg.wall_clock_budget_seconds == wall_clock
    assert cfg.ai_budget_seconds == ai_budget
    assert cfg.reserve_for_validation_percent == reserve_percent
    assert cfg.cloud_llm_allowed is False
    assert cfg.severity_floor is SeverityFloor.MEDIUM
    assert cfg.template_policy_id == "quick-default"


def test_resolved_config_is_frozen() -> None:
    cfg = _resolver().resolve(_TENANT_ID, QuickProfileName.BALANCED)
    assert isinstance(cfg, QuickScanConfig)
    with pytest.raises(ValidationError):
        cfg.profile = QuickProfileName.EXTENDED  # type: ignore[misc]
    with pytest.raises(ValidationError):
        cfg.cloud_llm_allowed = True  # type: ignore[misc]
    with pytest.raises(ValidationError):
        cfg.wall_clock_budget_seconds = 86_400  # type: ignore[misc]


def test_profile_request_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        QuickProfileRequest(profile="balanced", password="should-never-be-here")


@pytest.mark.parametrize("raw", ["turbo", "stealth", "production", "quick", "standard"])
def test_unknown_profile_raises_unknown_quick_profile(raw: str) -> None:
    with pytest.raises(UnknownQuickProfileError, match="unknown_quick_profile") as exc_info:
        _resolver().resolve(_TENANT_ID, raw)
    assert exc_info.value.code == "unknown_quick_profile"
    assert exc_info.value.profile == raw


def test_parse_quick_profile_name_unknown_raises() -> None:
    with pytest.raises(UnknownQuickProfileError, match="unknown_quick_profile") as exc_info:
        parse_quick_profile_name("turbo")
    assert exc_info.value.code == "unknown_quick_profile"
    assert exc_info.value.profile == "turbo"


def test_parse_quick_profile_name_accepts_enum_and_whitespace() -> None:
    assert parse_quick_profile_name(QuickProfileName.COMPACT) is QuickProfileName.COMPACT
    assert parse_quick_profile_name("  BALANCED  ") is QuickProfileName.BALANCED


def test_tenant_cannot_exceed_deployment_max_wall_clock() -> None:
    clamps = _clamps(max_wall_clock_seconds=400, balanced_wall_clock_seconds=400)
    tenant = _tenant(max_wall_clock_budget_seconds=2000)
    request = QuickProfileRequest(profile="balanced", wall_clock_budget_seconds=2000)
    cfg = _resolver(clamps).resolve(tenant, request)
    assert cfg.wall_clock_budget_seconds == 400
    assert cfg.wall_clock_budget_seconds <= 400


def test_tenant_cap_below_deployment_still_clamps_down() -> None:
    clamps = _clamps(max_wall_clock_seconds=1800)
    tenant = _tenant(max_wall_clock_budget_seconds=120)
    request = QuickProfileRequest(profile="extended", wall_clock_budget_seconds=1800)
    cfg = _resolver(clamps).resolve(tenant, request)
    assert cfg.wall_clock_budget_seconds == 120


def test_per_profile_deployment_clamp_caps_yaml_default() -> None:
    clamps = _clamps(compact_wall_clock_seconds=120)
    cfg = _resolver(clamps).resolve(_TENANT_ID, QuickProfileName.COMPACT)
    assert cfg.wall_clock_budget_seconds == 120


def test_cloud_llm_allowed_defaults_false() -> None:
    for profile in QuickProfileName:
        cfg = _resolver().resolve(_TENANT_ID, profile)
        assert cfg.cloud_llm_allowed is False
    requested = QuickProfileRequest(profile="balanced", cloud_llm_allowed=True)
    assert _resolver().resolve(_TENANT_ID, requested).cloud_llm_allowed is False


def test_cloud_llm_allowed_stays_false_when_yaml_disallows() -> None:
    request = QuickProfileRequest(profile="balanced", cloud_llm_allowed=True)
    tenant = _tenant(cloud_llm_allowed=True)
    clamps = _clamps(cloud_llm_allowed=True)
    cfg = _resolver(clamps).resolve(tenant, request)
    # YAML catalog defaults cloud_llm_allowed=false; every layer must allow.
    assert cfg.cloud_llm_allowed is False


def test_cloud_llm_allowed_requires_every_layer() -> None:
    catalog = _CATALOG.model_copy(
        update={
            "balanced": _CATALOG.balanced.model_copy(update={"cloud_llm_allowed": True}),
        }
    )
    resolver = QuickProfileResolver(catalog=catalog, clamps=_clamps(cloud_llm_allowed=True))
    request = QuickProfileRequest(profile="balanced", cloud_llm_allowed=True)

    denied_tenant = resolver.resolve(_tenant(cloud_llm_allowed=False), request)
    assert denied_tenant.cloud_llm_allowed is False

    denied_deploy = QuickProfileResolver(
        catalog=catalog, clamps=_clamps(cloud_llm_allowed=False)
    ).resolve(_tenant(cloud_llm_allowed=True), request)
    assert denied_deploy.cloud_llm_allowed is False

    allowed = resolver.resolve(_tenant(cloud_llm_allowed=True), request)
    assert allowed.cloud_llm_allowed is True
