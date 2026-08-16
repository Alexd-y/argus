"""Quick profile catalog: YAML defaults, tenant/deployment overrides, safe clamps.

Profile numbers (wall-clock, AI budget, reserve percent) live in
``backend/config/quick/profiles.yaml``. This module never treats those
values as scoring constants — it loads, merges, and clamps them.

Deployment env vars such as ``QUICK_COMPACT_WALL_CLOCK_SECONDS`` are
**upper clamps**, not business defaults.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Final, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    ValidationError,
)

from src.core.config import Settings
from src.core.config import settings as default_settings
from src.quick.schemas import QuickProfileName, SeverityFloor

logger = logging.getLogger(__name__)

_BACKEND_ROOT: Final[Path] = Path(__file__).resolve().parents[2]
DEFAULT_PROFILES_PATH: Final[Path] = _BACKEND_ROOT / "config" / "quick" / "profiles.yaml"

_SCHEMA_MAX_WALL_CLOCK: Final[int] = 86_400
_SCHEMA_MAX_AI: Final[int] = 86_400
_SCHEMA_MAX_TARGETS: Final[int] = 10_000
_SCHEMA_MAX_URLS: Final[int] = 10_000
_SCHEMA_MAX_CRAWL_DEPTH: Final[int] = 10
_SCHEMA_MAX_CONCURRENCY: Final[int] = 256
_SCHEMA_MAX_RESERVE_PERCENT: Final[int] = 50

# Fallback split of (wall_clock - reserve - ai) when YAML omits weights.
# Not profile defaults (those stay in YAML).
_DEFAULT_WORK_SPLIT: Final[dict[str, int]] = {
    "discovery": 40,
    "fingerprint": 25,
    "verification": 20,
    "report": 15,
}


class QuickProfileCatalogError(RuntimeError):
    """YAML missing, malformed, or missing a required profile."""

    code = "quick_profile_catalog_invalid"

    def __init__(self, message: str) -> None:
        super().__init__(message)


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class WorkSplitWeights(_Frozen):
    """Relative weights for remaining work seconds after reserve and AI."""

    discovery: StrictInt = Field(ge=1, le=10_000)
    fingerprint: StrictInt = Field(ge=1, le=10_000)
    verification: StrictInt = Field(ge=1, le=10_000)
    report: StrictInt = Field(ge=1, le=10_000)


class QuickProfileDefaults(_Frozen):
    """One YAML profile after validation. Includes budget extras not on QuickScanConfig."""

    wall_clock_budget_seconds: StrictInt = Field(ge=1, le=_SCHEMA_MAX_WALL_CLOCK)
    ai_budget_seconds: StrictInt = Field(ge=0, le=_SCHEMA_MAX_AI)
    reserve_for_validation_percent: StrictInt = Field(ge=0, le=_SCHEMA_MAX_RESERVE_PERCENT)
    max_targets: StrictInt = Field(ge=1, le=_SCHEMA_MAX_TARGETS)
    max_urls_per_host: StrictInt = Field(ge=1, le=_SCHEMA_MAX_URLS)
    crawl_depth: StrictInt = Field(ge=0, le=_SCHEMA_MAX_CRAWL_DEPTH)
    severity_floor: SeverityFloor = SeverityFloor.MEDIUM
    enable_ai: StrictBool = True
    enable_oast: StrictBool = True
    enable_headless_on_signal: StrictBool = True
    template_policy_id: StrictStr = Field(default="quick-default", min_length=1, max_length=128)
    cloud_llm_allowed: StrictBool = False
    request_budget: StrictInt = Field(ge=0)
    per_host_budget: StrictInt = Field(ge=0)
    concurrency_budget: StrictInt = Field(ge=1, le=_SCHEMA_MAX_CONCURRENCY)
    work_split_weights: WorkSplitWeights = Field(
        default_factory=lambda: WorkSplitWeights(
            discovery=_DEFAULT_WORK_SPLIT["discovery"],
            fingerprint=_DEFAULT_WORK_SPLIT["fingerprint"],
            verification=_DEFAULT_WORK_SPLIT["verification"],
            report=_DEFAULT_WORK_SPLIT["report"],
        )
    )


class TenantQuickLimits(_Frozen):
    """Optional per-tenant caps. Never raise a value above deployment clamps."""

    tenant_id: StrictStr = Field(min_length=1, max_length=36)
    max_wall_clock_budget_seconds: StrictInt | None = Field(default=None, ge=1, le=_SCHEMA_MAX_WALL_CLOCK)
    max_ai_budget_seconds: StrictInt | None = Field(default=None, ge=0, le=_SCHEMA_MAX_AI)
    max_targets: StrictInt | None = Field(default=None, ge=1, le=_SCHEMA_MAX_TARGETS)
    max_urls_per_host: StrictInt | None = Field(default=None, ge=1, le=_SCHEMA_MAX_URLS)
    max_crawl_depth: StrictInt | None = Field(default=None, ge=0, le=_SCHEMA_MAX_CRAWL_DEPTH)
    max_concurrency: StrictInt | None = Field(default=None, ge=1, le=_SCHEMA_MAX_CONCURRENCY)
    cloud_llm_allowed: StrictBool = False


class DeploymentQuickClamps(_Frozen):
    """Upper clamps from Settings. ``None`` means «YAML default is the cap»."""

    compact_wall_clock_seconds: StrictInt | None = Field(default=None, ge=1, le=_SCHEMA_MAX_WALL_CLOCK)
    balanced_wall_clock_seconds: StrictInt | None = Field(default=None, ge=1, le=_SCHEMA_MAX_WALL_CLOCK)
    extended_wall_clock_seconds: StrictInt | None = Field(default=None, ge=1, le=_SCHEMA_MAX_WALL_CLOCK)
    max_wall_clock_seconds: StrictInt | None = Field(default=None, ge=1, le=_SCHEMA_MAX_WALL_CLOCK)
    cloud_llm_allowed: StrictBool = False
    max_concurrency: StrictInt = Field(default=10, ge=1, le=_SCHEMA_MAX_CONCURRENCY)

    @classmethod
    def from_settings(cls, app_settings: Settings) -> Self:
        return cls(
            compact_wall_clock_seconds=app_settings.quick_compact_wall_clock_seconds,
            balanced_wall_clock_seconds=app_settings.quick_balanced_wall_clock_seconds,
            extended_wall_clock_seconds=app_settings.quick_extended_wall_clock_seconds,
            max_wall_clock_seconds=app_settings.quick_max_wall_clock_seconds,
            cloud_llm_allowed=bool(app_settings.quick_cloud_llm_allowed),
            max_concurrency=max(1, int(app_settings.active_scan_max_concurrent_jobs)),
        )

    def wall_clock_cap_for(self, profile: QuickProfileName, yaml_default: int) -> int:
        match profile:
            case QuickProfileName.COMPACT:
                per_profile = self.compact_wall_clock_seconds
            case QuickProfileName.BALANCED:
                per_profile = self.balanced_wall_clock_seconds
            case QuickProfileName.EXTENDED:
                per_profile = self.extended_wall_clock_seconds
            case _:
                raise QuickProfileCatalogError(f"unknown_quick_profile:{profile}")
        cap = per_profile if per_profile is not None else yaml_default
        global_cap = (
            self.max_wall_clock_seconds
            if self.max_wall_clock_seconds is not None
            else _SCHEMA_MAX_WALL_CLOCK
        )
        return max(1, min(cap, global_cap, _SCHEMA_MAX_WALL_CLOCK))


class QuickProfileCatalog(_Frozen):
    schema_version: StrictInt = Field(ge=1)
    compact: QuickProfileDefaults
    balanced: QuickProfileDefaults
    extended: QuickProfileDefaults

    def get(self, name: QuickProfileName) -> QuickProfileDefaults:
        match name:
            case QuickProfileName.COMPACT:
                return self.compact
            case QuickProfileName.BALANCED:
                return self.balanced
            case QuickProfileName.EXTENDED:
                return self.extended
            case _:
                raise QuickProfileCatalogError(f"unknown_quick_profile:{name}")


def _require_mapping(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QuickProfileCatalogError(f"quick_profile_catalog_invalid:{label}")
    return value


def _parse_profile_block(raw: dict[str, Any], name: str) -> QuickProfileDefaults:
    payload = dict(raw)
    weights = payload.get("work_split_weights")
    if weights is None:
        payload["work_split_weights"] = dict(_DEFAULT_WORK_SPLIT)
    try:
        return QuickProfileDefaults.model_validate(payload)
    except ValidationError as exc:
        raise QuickProfileCatalogError(f"quick_profile_invalid:{name}") from exc


def load_quick_profiles(path: Path | None = None) -> QuickProfileCatalog:
    """Load and validate ``profiles.yaml``. Fail-closed on missing/invalid catalog."""
    catalog_path = path if path is not None else DEFAULT_PROFILES_PATH
    if not catalog_path.is_file():
        raise QuickProfileCatalogError("quick_profile_catalog_missing")
    try:
        loaded = yaml.safe_load(catalog_path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        raise QuickProfileCatalogError("quick_profile_catalog_unreadable") from exc
    root = _require_mapping(loaded, "root")
    profiles = _require_mapping(root.get("profiles"), "profiles")
    required = (
        QuickProfileName.COMPACT.value,
        QuickProfileName.BALANCED.value,
        QuickProfileName.EXTENDED.value,
    )
    missing = [name for name in required if name not in profiles]
    if missing:
        raise QuickProfileCatalogError(f"quick_profile_catalog_missing_profiles:{','.join(missing)}")
    schema_version = int(root.get("schema_version") or 1)
    catalog = QuickProfileCatalog(
        schema_version=schema_version,
        compact=_parse_profile_block(_require_mapping(profiles["compact"], "compact"), "compact"),
        balanced=_parse_profile_block(_require_mapping(profiles["balanced"], "balanced"), "balanced"),
        extended=_parse_profile_block(_require_mapping(profiles["extended"], "extended"), "extended"),
    )
    logger.info(
        "quick_profiles_loaded",
        extra={"schema_version": catalog.schema_version, "path": str(catalog_path)},
    )
    return catalog


def default_clamps() -> DeploymentQuickClamps:
    return DeploymentQuickClamps.from_settings(default_settings)


def clamp_int(value: int, *, lo: int, hi: int) -> int:
    return max(lo, min(hi, value))


__all__ = [
    "DEFAULT_PROFILES_PATH",
    "DeploymentQuickClamps",
    "QuickProfileCatalog",
    "QuickProfileCatalogError",
    "QuickProfileDefaults",
    "TenantQuickLimits",
    "WorkSplitWeights",
    "clamp_int",
    "default_clamps",
    "load_quick_profiles",
]
