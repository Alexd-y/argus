"""Tool registrability gate (R9) — signed descriptor is the single source of truth.

A tool may only be registered for MCP / selected by the planner when ALL of the
following hold:

* it has a signed descriptor in the tool registry (source of truth),
* its executable is present in the sandbox manifest,
* a parser is wired for it (so output never becomes a fabricated finding — see
  ``dispatch_parse_strict`` / R9.3), and
* the resolved scan profile permits its risk level.

The gate is pure and testable: it takes plain descriptor-like objects and
allow-lists, and returns a machine-readable :class:`RegistrabilityResult`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Protocol

from src.core.structured_events import (
    EVENT_TOOL_SELECTED,
    EVENT_TOOL_SKIPPED,
    EVENT_TOOL_UNAVAILABLE,
    emit_event,
)

logger = logging.getLogger(__name__)

# Reason codes (R12 error contract vocabulary).
REASON_DESCRIPTOR_MISSING: Final[str] = "descriptor_missing"
REASON_EXECUTABLE_MISSING: Final[str] = "executable_missing"
REASON_PARSER_UNAVAILABLE: Final[str] = "parser_unavailable"
REASON_PROFILE_CAPABILITY_DENIED: Final[str] = "profile_capability_denied"

_RISK_ORDER: Final[dict[str, int]] = {
    "passive": 0,
    "info": 0,
    "informational": 0,
    "safe": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
    "destructive": 4,
}

# profile.payload_risk_ceiling → max tool risk rank allowed.
_CEILING_RANK: Final[dict[str, int]] = {
    "low": 1,  # quick — passive/low only
    "medium": 2,  # light — up to medium
    "high": 4,  # deep — everything incl. destructive
}


class DescriptorLike(Protocol):
    tool_id: str
    command_template: list[str]
    risk_level: Any
    requires_approval: bool


@dataclass(frozen=True, slots=True)
class RegistrabilityResult:
    tool_id: str
    registrable: bool
    reasons: tuple[str, ...]

    @property
    def reason(self) -> str | None:
        return self.reasons[0] if self.reasons else None


def _risk_rank(risk_level: Any) -> int:
    value = getattr(risk_level, "value", risk_level)
    return _RISK_ORDER.get(str(value).strip().lower(), 4)  # unknown → treat as destructive


def _executable_of(descriptor: DescriptorLike) -> str:
    template = getattr(descriptor, "command_template", None) or []
    return str(template[0]) if template else ""


def load_known_executables(path: Path | None = None) -> frozenset[str]:
    """Load executable names from ``infra/sandbox/expected_executables.json``."""
    if path is None:
        path = (
            Path(__file__).resolve().parents[3]
            / "infra"
            / "sandbox"
            / "expected_executables.json"
        )
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return frozenset()
    names = {str(e.get("name", "")).strip() for e in data.get("executables", []) if e.get("name")}
    return frozenset(n for n in names if n)


def evaluate_tool_registrability(
    descriptor: DescriptorLike | None,
    *,
    parser_tool_ids: frozenset[str],
    known_executables: frozenset[str] | None = None,
    payload_risk_ceiling: str | None = None,
    require_executable_manifest: bool = True,
) -> RegistrabilityResult:
    """Return whether ``descriptor`` is registrable + machine-readable reasons."""
    if descriptor is None:
        return RegistrabilityResult("<unknown>", False, (REASON_DESCRIPTOR_MISSING,))

    tool_id = str(descriptor.tool_id)
    reasons: list[str] = []

    executable = _executable_of(descriptor)
    manifest_miss = (
        require_executable_manifest
        and known_executables is not None
        and executable not in known_executables
    )
    if not executable or manifest_miss:
        reasons.append(REASON_EXECUTABLE_MISSING)

    if tool_id not in parser_tool_ids:
        reasons.append(REASON_PARSER_UNAVAILABLE)

    if payload_risk_ceiling is not None:
        ceiling = _CEILING_RANK.get(str(payload_risk_ceiling).strip().lower(), 4)
        if _risk_rank(descriptor.risk_level) > ceiling:
            reasons.append(REASON_PROFILE_CAPABILITY_DENIED)

    return RegistrabilityResult(tool_id, not reasons, tuple(reasons))


def registrable_tool_ids(
    descriptors: list[DescriptorLike],
    *,
    parser_tool_ids: frozenset[str],
    known_executables: frozenset[str] | None = None,
    payload_risk_ceiling: str | None = None,
    require_executable_manifest: bool = True,
    emit: bool = False,
    scan_id: str | None = None,
    tenant_id: str | None = None,
    scan_profile: str | None = None,
) -> frozenset[str]:
    """Return the set of tool_ids that are registrable (allow-list for R8/planner)."""
    allowed: set[str] = set()
    for descriptor in descriptors:
        result = evaluate_tool_registrability(
            descriptor,
            parser_tool_ids=parser_tool_ids,
            known_executables=known_executables,
            payload_risk_ceiling=payload_risk_ceiling,
            require_executable_manifest=require_executable_manifest,
        )
        if result.registrable:
            allowed.add(result.tool_id)
            if emit:
                emit_event(
                    EVENT_TOOL_SELECTED,
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    scan_profile=scan_profile,
                    tool_id=result.tool_id,
                )
        elif emit:
            event = (
                EVENT_TOOL_UNAVAILABLE
                if REASON_EXECUTABLE_MISSING in result.reasons
                or REASON_PARSER_UNAVAILABLE in result.reasons
                else EVENT_TOOL_SKIPPED
            )
            emit_event(
                event,
                tenant_id=tenant_id,
                scan_id=scan_id,
                scan_profile=scan_profile,
                tool_id=result.tool_id,
                reason_code=result.reason,
                level=logging.WARNING,
            )
    return frozenset(allowed)


def should_register_mcp_tool(
    descriptor: DescriptorLike | None,
    *,
    parser_tool_ids: frozenset[str],
    known_executables: frozenset[str] | None = None,
) -> bool:
    """MCP registration gate (R9.2): never publish a knowingly-broken tool."""
    return evaluate_tool_registrability(
        descriptor,
        parser_tool_ids=parser_tool_ids,
        known_executables=known_executables,
    ).registrable


__all__ = [
    "REASON_DESCRIPTOR_MISSING",
    "REASON_EXECUTABLE_MISSING",
    "REASON_PARSER_UNAVAILABLE",
    "REASON_PROFILE_CAPABILITY_DENIED",
    "RegistrabilityResult",
    "evaluate_tool_registrability",
    "load_known_executables",
    "registrable_tool_ids",
    "should_register_mcp_tool",
]
