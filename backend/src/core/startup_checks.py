"""Startup configuration validation — surface risky/foot-gun config early.

Runs once at app (and optionally worker) startup. Logs the EFFECTIVE recon plan
and LLM report routing, and warns when a config combination would silently
degrade output — e.g. a RECON_TOOL_SELECTION that excludes the base
Target-Intelligence steps (the regression that left every report's TI blank),
or a reporting phase pinned to a slow local model while a cloud report key is set.

Warnings only — never raises; a bad config should be loud, not fatal.
"""

from __future__ import annotations

import logging
import os

logger = logging.getLogger(__name__)

# The recon steps that produce Target Intelligence (WHOIS/DNS/email-auth/tech).
_CORE_TI_STEPS = ("whois", "dig", "dns_depth", "http_surface")


def validate_startup_config() -> list[str]:
    """Log the effective config and return a list of human-readable warnings."""
    warnings: list[str] = []

    # --- Recon: the default-config plan must keep the core TI steps -----------
    try:
        from src.recon.recon_runtime import build_recon_runtime_config
        from src.recon.step_registry import plan_recon_steps

        cfg = build_recon_runtime_config({})
        plan = {s.value for s in plan_recon_steps(cfg)}
        missing = [s for s in _CORE_TI_STEPS if s not in plan]
        logger.info(
            "startup_recon_plan",
            extra={
                "event": "startup_recon_plan",
                "mode": cfg.mode,
                "tool_selection": (sorted(cfg.tool_selection) if cfg.tool_selection else None),
                "plan": sorted(plan),
                "core_ti_present": not missing,
            },
        )
        if missing and cfg.mode != "passive":
            warnings.append(
                f"recon plan is missing core Target-Intelligence steps {missing} "
                "(check RECON_TOOL_SELECTION / RECON_MODE) — report TI will be sparse"
            )
    except Exception as exc:  # noqa: BLE001 — defensive; never block startup
        logger.warning(
            "startup_recon_plan_check_failed",
            extra={"event": "startup_recon_plan_check_failed", "error_type": type(exc).__name__},
        )

    # --- LLM: reporting should not run on the slow local path if cloud is set --
    try:
        from src.llm.phase_routing import get_phase_route, is_enabled

        if is_enabled():
            route = get_phase_route("reporting")
            cloud_report_key = bool(
                (os.environ.get("DEEPSEEK_API_KEY") or "").strip()
                or (os.environ.get("OPENROUTER_API_KEY") or "").strip()
            )
            if route and route.mode != "cloud" and cloud_report_key:
                warnings.append(
                    f"reporting phase mode='{route.mode}' but a cloud report key is configured — "
                    "report AI may run on the slow local path; consider mode: cloud"
                )
    except Exception:  # noqa: BLE001
        pass

    for w in warnings:
        logger.warning(
            "startup_config_warning", extra={"event": "startup_config_warning", "warning": w}
        )
    return warnings
