"""Shared Quick scan-create helpers for REST and MCP (QUICK-007).

Feature-flag and payload conflict checks live here so MCP cannot bypass
the REST policy path. Quick never inherits lab_unrestricted options.
"""

from __future__ import annotations

import logging
import uuid
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.config import settings
from src.core.datetime_format import format_created_at_iso_z
from src.execution_mode.mode import ExecutionMode, parse_execution_mode
from src.quick.audit import emit_quick_audit_event
from src.quick.budget import QuickBudget, QuickBudgetManager, compute_deadline_at
from src.quick.metrics import record_budget_used_ratio
from src.quick.models import QuickScanConfigRow, QuickScanPlanRow
from src.quick.profiles import TenantQuickLimits
from src.quick.resolver import (
    QuickProfileRequest,
    QuickProfileResolver,
    UnknownQuickProfileError,
)
from src.quick.schemas import QuickProfileName, QuickScanConfig, SeverityFloor

logger = logging.getLogger(__name__)

QUICK_MODE_DISABLED = "quick_mode_disabled"
CONFLICTING_EXECUTION_MODE = "conflicting_execution_mode"
UNKNOWN_QUICK_PROFILE = "unknown_quick_profile"
PLAN_NOT_APPLICABLE = "plan_not_applicable"
UNSUPPORTED_EXECUTION_MODE = "unsupported_execution_mode"
RAW_COMMAND_NOT_ALLOWED = "raw_command_not_allowed"

_QUICK_PLAN_STAGES: tuple[str, ...] = (
    "discovery",
    "fingerprint",
    "test",
    "verify",
    "triage",
    "report",
)

_LAB_OPTION_KEYS: frozenset[str] = frozenset(
    {
        "lab_lease",
        "lab_lease_id",
        "lab_lease_active",
        "intentional_vulnerable_lab",
        "lab_profile",
        "lab_allowed_targets",
        "argus_lab_allowed_targets",
        "active_injection_mode",
    }
)

_FORBIDDEN_COMMAND_KEYS: frozenset[str] = frozenset(
    {
        "argv",
        "command",
        "cmdline",
        "cmd",
        "shell",
        "command_string",
        "command_template",
    }
)


class QuickCreateError(ValueError):
    """API/MCP-stable create error. ``code`` maps to HTTP/MCP error codes."""

    code = "quick_create_error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        self.code = code or type(self).code
        super().__init__(message)


class QuickModeDisabledError(QuickCreateError):
    code = QUICK_MODE_DISABLED

    def __init__(self, message: str = "Quick mode is disabled") -> None:
        super().__init__(message, code=QUICK_MODE_DISABLED)


class ConflictingExecutionModeError(QuickCreateError):
    code = CONFLICTING_EXECUTION_MODE

    def __init__(self, message: str = "lab_unrestricted cannot be combined with quick options") -> None:
        super().__init__(message, code=CONFLICTING_EXECUTION_MODE)


class RawCommandNotAllowedError(QuickCreateError):
    code = RAW_COMMAND_NOT_ALLOWED

    def __init__(self, message: str = "Raw argv/command strings are not allowed") -> None:
        super().__init__(message, code=RAW_COMMAND_NOT_ALLOWED)


def error_detail(message: str, code: str) -> dict[str, str]:
    """HTTPException.detail payload matching api-contracts `{error, code}`."""
    return {"error": message, "code": code}


def is_quick_mode_enabled() -> bool:
    """Global feature flag. Default false (fail-closed)."""
    return bool(settings.quick_mode_enabled)


def parse_requested_execution_mode(raw: str | ExecutionMode | None) -> ExecutionMode:
    """Parse optional API/MCP execution_mode. Empty → production."""
    if raw is None or raw == "":
        return ExecutionMode.PRODUCTION
    try:
        return parse_execution_mode(raw)
    except ValueError as exc:
        raise QuickCreateError(
            "Unsupported execution_mode",
            code=UNSUPPORTED_EXECUTION_MODE,
        ) from exc


def mapping_has_quick_payload(raw: Mapping[str, Any] | None) -> bool:
    return bool(raw)


def assert_execution_mode_payload(
    execution_mode: ExecutionMode,
    *,
    has_quick_payload: bool,
    enabled: bool | None = None,
) -> None:
    """Reject flag-off quick and lab+quick combinations. Never silent-fallback."""
    if execution_mode is ExecutionMode.LAB_UNRESTRICTED and has_quick_payload:
        raise ConflictingExecutionModeError()
    flag_on = is_quick_mode_enabled() if enabled is None else enabled
    if execution_mode is ExecutionMode.QUICK and not flag_on:
        emit_quick_audit_event(
            "quick.policy",
            scan_id="",
            payload={"decision": QUICK_MODE_DISABLED, "execution_mode": execution_mode.value},
        )
        raise QuickModeDisabledError()
    if execution_mode is ExecutionMode.QUICK:
        emit_quick_audit_event(
            "quick.policy",
            scan_id="",
            payload={"decision": "allowed", "execution_mode": execution_mode.value},
        )


def reject_raw_command_fields(payload: Mapping[str, Any] | None) -> None:
    """Reject argv/command strings at any supported nesting level."""
    if not payload:
        return
    for key in _FORBIDDEN_COMMAND_KEYS:
        if key in payload:
            raise RawCommandNotAllowedError()
    nested = payload.get("scan_options")
    if isinstance(nested, Mapping):
        for key in _FORBIDDEN_COMMAND_KEYS:
            if key in nested:
                raise RawCommandNotAllowedError()
    params = payload.get("params")
    if isinstance(params, Mapping):
        for key in _FORBIDDEN_COMMAND_KEYS:
            if key in params:
                raise RawCommandNotAllowedError()
    quick = payload.get("quick")
    if isinstance(quick, Mapping):
        for key in _FORBIDDEN_COMMAND_KEYS:
            if key in quick:
                raise RawCommandNotAllowedError()


def strip_lab_options(options: dict[str, Any]) -> dict[str, Any]:
    """Remove lab_unrestricted inheritance from a Quick options dict."""
    cleaned = {key: value for key, value in options.items() if key not in _LAB_OPTION_KEYS}
    flags = cleaned.get("scan_approval_flags")
    if isinstance(flags, dict):
        cleaned["scan_approval_flags"] = dict(flags)
    cleaned["lab_lease_active"] = False
    return cleaned


def profile_request_from_mapping(raw: Mapping[str, Any] | None) -> QuickProfileRequest:
    """Build a resolver request. Unknown profile names fail in the resolver."""
    if not raw:
        return QuickProfileRequest(profile=QuickProfileName.BALANCED.value)
    severity_raw = raw.get("severity_floor")
    severity: SeverityFloor | None = None
    if severity_raw is not None and str(severity_raw).strip():
        try:
            severity = SeverityFloor(str(severity_raw).strip().lower())
        except ValueError as exc:
            raise UnknownQuickProfileError(str(severity_raw)) from exc
    try:
        return QuickProfileRequest(
            profile=str(raw.get("profile") or QuickProfileName.BALANCED.value),
            wall_clock_budget_seconds=_optional_int(raw.get("wall_clock_budget_seconds")),
            ai_budget_seconds=_optional_int(raw.get("ai_budget_seconds")),
            reserve_for_validation_percent=_optional_int(raw.get("reserve_for_validation_percent")),
            max_targets=_optional_int(raw.get("max_targets")),
            max_urls_per_host=_optional_int(raw.get("max_urls_per_host")),
            crawl_depth=_optional_int(raw.get("crawl_depth")),
            severity_floor=severity,
            enable_ai=_optional_bool(raw.get("enable_ai")),
            enable_oast=_optional_bool(raw.get("enable_oast")),
            enable_headless_on_signal=_optional_bool(raw.get("enable_headless_on_signal")),
            authenticated_context_id=_optional_str(raw.get("authenticated_context_id")),
            template_policy_id=_optional_str(raw.get("template_policy_id")),
            cloud_llm_allowed=_optional_bool(raw.get("cloud_llm_allowed")),
        )
    except PydanticValidationError as exc:
        raise QuickCreateError("Invalid quick options", code="validation_error") from exc


def resolve_quick_runtime(
    *,
    tenant_id: str,
    quick_payload: Mapping[str, Any] | None,
    started_at: datetime | None = None,
    resolver: QuickProfileResolver | None = None,
    budget_manager: QuickBudgetManager | None = None,
) -> tuple[QuickScanConfig, QuickBudget, datetime]:
    """Resolve frozen config + budget + deadline. No network, no secrets in logs."""
    origin = started_at if started_at is not None else datetime.now(UTC)
    active_resolver = resolver if resolver is not None else QuickProfileResolver()
    manager = budget_manager if budget_manager is not None else QuickBudgetManager()
    tenant_limits = TenantQuickLimits(tenant_id=tenant_id)
    config = active_resolver.resolve(tenant_limits, profile_request_from_mapping(quick_payload))
    budget = manager.build_budget(config, tenant_limits)
    deadline = compute_deadline_at(origin, config.wall_clock_budget_seconds)
    logger.info(
        "quick_runtime_resolved",
        extra={
            "tenant_id": tenant_id,
            "profile": config.profile.value,
            "wall_clock_budget_seconds": config.wall_clock_budget_seconds,
            "cloud_llm_allowed": config.cloud_llm_allowed,
        },
    )
    record_budget_used_ratio(0.0)
    emit_quick_audit_event(
        "quick.create",
        scan_id="",
        tenant_id=tenant_id,
        payload={
            "profile": config.profile.value,
            "wall_clock_budget_seconds": config.wall_clock_budget_seconds,
            "cloud_llm_allowed": config.cloud_llm_allowed,
            "authenticated_context_id": config.authenticated_context_id,
        },
    )
    return config, budget, deadline


def overlay_quick_options(
    options: dict[str, Any],
    *,
    config: QuickScanConfig,
    budget: QuickBudget,
    deadline_at: datetime,
) -> dict[str, Any]:
    """Stamp Quick fields onto scan.options. Strips lab keys. No credentials."""
    overlayed = strip_lab_options(dict(options))
    overlayed["execution_mode"] = ExecutionMode.QUICK.value
    overlayed["scan_mode"] = "quick"
    overlayed["scanType"] = "quick"
    overlayed["quick_profile"] = config.profile.value
    overlayed["deadline_at"] = format_created_at_iso_z(deadline_at)
    overlayed["quick"] = _public_quick_config(config)
    overlayed["quick_budget"] = budget.model_dump(mode="json")
    overlayed["lab_lease_active"] = False
    return overlayed


def persist_quick_rows(
    session: AsyncSession,
    *,
    tenant_id: str,
    scan_id: str,
    config: QuickScanConfig,
    budget: QuickBudget,
    deadline_at: datetime,
) -> None:
    """Write config + plan stub. Caller owns commit. No secrets in payload."""
    session.add(
        QuickScanConfigRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            scan_id=scan_id,
            profile=config.profile.value,
            wall_clock_budget_seconds=config.wall_clock_budget_seconds,
            ai_budget_seconds=config.ai_budget_seconds,
            reserve_for_validation_percent=config.reserve_for_validation_percent,
            max_targets=config.max_targets,
            max_urls_per_host=config.max_urls_per_host,
            crawl_depth=config.crawl_depth,
            severity_floor=config.severity_floor.value,
            enable_ai=config.enable_ai,
            enable_oast=config.enable_oast,
            enable_headless_on_signal=config.enable_headless_on_signal,
            authenticated_context_id=config.authenticated_context_id,
            template_policy_id=config.template_policy_id,
            cloud_llm_allowed=config.cloud_llm_allowed,
            deadline_at=deadline_at,
            payload=_public_quick_config(config),
        )
    )
    session.add(
        QuickScanPlanRow(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            scan_id=scan_id,
            plan_version=1,
            prompt_version="pending",
            model_route="deterministic",
            deadline_at=deadline_at,
            budget=budget.model_dump(mode="json"),
            stages=list(_QUICK_PLAN_STAGES),
            tasks=[],
            fallbacks=["deterministic_planner"],
            coverage_intent=[],
            assumptions=["awaiting_fingerprint"],
        )
    )
    emit_quick_audit_event(
        "quick.create",
        scan_id=scan_id,
        tenant_id=tenant_id,
        payload={
            "profile": config.profile.value,
            "deadline_at": deadline_at.isoformat(),
            "plan_version": 1,
        },
    )


def budget_view_from_mapping(raw: Mapping[str, Any] | None) -> dict[str, Any] | None:
    """Project a budget mapping to API-safe fields."""
    if not raw:
        return None
    keys = (
        "wall_clock_budget_seconds",
        "discovery_budget_seconds",
        "fingerprint_budget_seconds",
        "verification_budget_seconds",
        "ai_budget_seconds",
        "report_budget_seconds",
        "request_budget",
        "per_host_budget",
        "concurrency_budget",
        "reserve_for_validation_percent",
    )
    out: dict[str, Any] = {}
    for key in keys:
        value = raw.get(key)
        if value is not None:
            out[key] = value
    if "wall_clock_budget_seconds" not in out:
        return None
    return out


def _public_quick_config(config: QuickScanConfig) -> dict[str, Any]:
    dumped = config.model_dump(mode="json")
    # authenticated_context_id is a store ref, not a secret; still omit from options
    # overlay that workers log. Persist it only on the dedicated config row.
    dumped.pop("authenticated_context_id", None)
    return dumped


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    return int(value)


def _optional_bool(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    return None


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


__all__ = [
    "CONFLICTING_EXECUTION_MODE",
    "PLAN_NOT_APPLICABLE",
    "QUICK_MODE_DISABLED",
    "RAW_COMMAND_NOT_ALLOWED",
    "UNKNOWN_QUICK_PROFILE",
    "UNSUPPORTED_EXECUTION_MODE",
    "ConflictingExecutionModeError",
    "QuickCreateError",
    "QuickModeDisabledError",
    "RawCommandNotAllowedError",
    "assert_execution_mode_payload",
    "budget_view_from_mapping",
    "error_detail",
    "is_quick_mode_enabled",
    "mapping_has_quick_payload",
    "overlay_quick_options",
    "parse_requested_execution_mode",
    "persist_quick_rows",
    "profile_request_from_mapping",
    "reject_raw_command_fields",
    "resolve_quick_runtime",
    "strip_lab_options",
]
