"""The three DWM gates (all required) + status resolution.

A DWM sweep runs ONLY when ALL three hold:
1. global:      ``settings.dark_web_monitoring_enabled``
2. per-scan:    ``options.dark_web.enabled``
3. entitlement: the tenant is entitled (DWM is a paid Asgard/Valhalla capability)

When any gate fails, the sweep does not run and the report carries an explicit
status (``disabled`` / ``not_entitled`` / ``not_collected``) — never fabricated
data ("not run != not found").
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.core.config import settings
from src.intel.dark_web.contracts import DarkWebReportStatus
from src.recon.scan_options_dark_web import scan_dark_web_flags


@dataclass(frozen=True)
class DarkWebGateDecision:
    allowed: bool
    status: DarkWebReportStatus
    flags: dict[str, Any]


def resolve_entitlement(*, tenant_entitled: bool | None = None) -> bool:
    """Resolve whether the tenant is entitled to DWM — FAIL CLOSED.

    DWM is a paid capability (Asgard/Valhalla). Entitlement MUST be resolved
    server-side (see ``entitlement.tenant_has_dwm_entitlement``) and passed in as
    ``tenant_entitled``. When it is unknown (``None``), the tenant is treated as
    NOT entitled — we never fall open, and we never trust a client-supplied
    options flag (that would be an authorization bypass).
    """

    return bool(tenant_entitled) if tenant_entitled is not None else False


def pipeline_prefilter_allows(
    options: dict[str, Any] | None,
    *,
    settings_enabled: bool | None = None,
) -> tuple[bool, DarkWebReportStatus, dict[str, Any]]:
    """The two gates checkable WITHOUT a DB session: global flag + per-scan opt-in.

    Used by the pipeline triggers (which have no session) to decide whether to
    enqueue the sweep task. The task is the AUTHORITATIVE gate — it resolves
    entitlement server-side and denies if the tenant is not entitled. The
    prefilter deliberately does NOT assume entitlement.
    """

    flags = scan_dark_web_flags(options)
    global_on = (
        bool(getattr(settings, "dark_web_monitoring_enabled", False))
        if settings_enabled is None
        else bool(settings_enabled)
    )
    if not global_on or not bool(flags["enabled"]):
        return (False, DarkWebReportStatus.DISABLED, flags)
    return (True, DarkWebReportStatus.NOT_COLLECTED, flags)


def evaluate_dark_web_gate(
    options: dict[str, Any] | None,
    *,
    settings_enabled: bool | None = None,
    tenant_entitled: bool | None = None,
) -> DarkWebGateDecision:
    """Evaluate the three gates and return an allow/deny + explicit status.

    ``tenant_entitled`` MUST be resolved server-side by the caller (fail-closed:
    ``None`` => NOT_ENTITLED). Callers without a session should use
    :func:`pipeline_prefilter_allows` instead and let the task be authoritative.
    """

    allowed_prefilter, status, flags = pipeline_prefilter_allows(
        options, settings_enabled=settings_enabled
    )
    if not allowed_prefilter:
        return DarkWebGateDecision(False, status, flags)
    if not resolve_entitlement(tenant_entitled=tenant_entitled):
        return DarkWebGateDecision(False, DarkWebReportStatus.NOT_ENTITLED, flags)
    # All three gates pass; the sweep may run. Until it does, status is "not_collected".
    return DarkWebGateDecision(True, DarkWebReportStatus.NOT_COLLECTED, flags)


__all__ = [
    "DarkWebGateDecision",
    "evaluate_dark_web_gate",
    "pipeline_prefilter_allows",
    "resolve_entitlement",
]
