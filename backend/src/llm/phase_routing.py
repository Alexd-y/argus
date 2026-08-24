"""Phase-aware LLM routing (in-process).

Resolves a per-phase execution intent (primary mode + fallback + reviewer +
evidence contract + degrade strategy) from ``backend/config/llm/phase_routing.yaml``.

Backward compatible: when ``ARGUS_PHASE_ROUTING_ENABLED`` is not truthy, or a phase
is not listed, callers fall back to the legacy facade routing. This module performs
NO LLM calls — it only resolves intent; execution stays in ``facade.py`` which reuses
the existing adapters/task_router and their provider+key plumbing.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_VALID_MODES = frozenset({"cloud", "wrb", "qwythos", "small"})
_VALID_FALLBACKS = frozenset({"cloud", "wrb", "qwythos", "small", "none"})


@dataclass(frozen=True)
class PhaseRoute:
    phase: str
    primary_alias: str
    mode: str  # "cloud" | "wrb" | "qwythos" | "small"
    fallback: str  # "cloud" | "wrb" | "qwythos" | "small" | "none"
    reviewer_alias: str | None = None
    evidence_contract: str | None = None
    degrade: str | None = None


_routes_cache: dict[str, PhaseRoute] | None = None
_version: str = ""


def _config_path() -> Path:
    override = (os.environ.get("ARGUS_PHASE_ROUTING_CONFIG") or "").strip()
    if override:
        return Path(override)
    # backend/src/llm/phase_routing.py -> backend/config/llm/phase_routing.yaml
    return Path(__file__).resolve().parents[2] / "config" / "llm" / "phase_routing.yaml"


def is_enabled() -> bool:
    return (os.environ.get("ARGUS_PHASE_ROUTING_ENABLED") or "").strip().lower() in (
        "1",
        "true",
        "yes",
        "on",
    )


def _load_routes() -> dict[str, PhaseRoute]:
    global _routes_cache, _version
    if _routes_cache is not None:
        return _routes_cache

    routes: dict[str, PhaseRoute] = {}
    path = _config_path()
    try:
        import yaml

        with open(path, encoding="utf-8") as fh:
            data = yaml.safe_load(fh) or {}
    except FileNotFoundError:
        logger.info("phase_routing_config_absent", extra={"path": str(path)})
        _routes_cache = routes
        return routes
    except Exception as exc:  # pragma: no cover — defensive
        logger.warning("phase_routing_config_load_failed", extra={"error": str(exc)})
        _routes_cache = routes
        return routes

    _version = str(data.get("version") or "")

    # Validate alias labels against the registry (warn-only; reviewer aliases such
    # as "argus-judge" are intentionally not provider-backed).
    try:
        from src.llm.model_aliases import get_alias_registry

        known = {a.alias for a in get_alias_registry().list_all()}
    except Exception:  # pragma: no cover — defensive
        known = set()

    for phase, raw in (data.get("phases") or {}).items():
        if not isinstance(raw, dict):
            continue
        mode = str(raw.get("mode") or "wrb").strip().lower()
        fallback = str(raw.get("fallback") or "none").strip().lower()
        if mode not in _VALID_MODES:
            logger.warning("phase_routing_invalid_mode", extra={"phase": phase, "mode": mode})
            mode = "wrb"
        if fallback not in _VALID_FALLBACKS:
            fallback = "none"
        primary_alias = str(raw.get("primary_alias") or "").strip()
        if known and primary_alias and primary_alias not in known:
            logger.warning(
                "phase_routing_unknown_alias",
                extra={"phase": phase, "alias": primary_alias},
            )
        routes[str(phase)] = PhaseRoute(
            phase=str(phase),
            primary_alias=primary_alias,
            mode=mode,
            fallback=fallback,
            reviewer_alias=(str(raw["reviewer_alias"]).strip() if raw.get("reviewer_alias") else None),
            evidence_contract=(str(raw["evidence_contract"]).strip() if raw.get("evidence_contract") else None),
            degrade=(str(raw["degrade"]).strip() if raw.get("degrade") else None),
        )

    _routes_cache = routes
    return routes


def get_phase_route(phase: str | None) -> PhaseRoute | None:
    """Return the route for *phase*, or None when routing is disabled/unmapped."""
    if not phase or not is_enabled():
        return None
    return _load_routes().get(str(phase))


def reset_cache() -> None:
    """Test helper: drop the cached routes so the next access reloads the YAML."""
    global _routes_cache, _version
    _routes_cache = None
    _version = ""
