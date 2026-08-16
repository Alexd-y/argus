"""Reason codes and denylists for classes Quick never schedules by default."""

from __future__ import annotations

from enum import StrEnum
from typing import Final

from src.capabilities.schemas import CapabilityNode, ProductionRisk


class QuickDisallowedReason(StrEnum):
    """Stable reason codes for Quick coverage gaps and planner exclusions."""

    NOT_SCHEDULED_BY_QUICK_PROFILE = "not_scheduled_by_quick_profile"
    OUT_OF_SCOPE = "out_of_scope"
    QUICK_INELIGIBLE = "quick_ineligible"
    BRUTE_FORCE = "brute_force_excluded"
    EXHAUSTIVE_FUZZ = "exhaustive_fuzz_excluded"
    DESTRUCTIVE = "destructive_excluded"
    REVERSE_ENGINEERING = "heavy_re_excluded"
    POST_EXPLOITATION = "post_exploitation_excluded"
    EXPLOITATION = "exploitation_excluded"
    CLUSTERBOMB = "clusterbomb_excluded"
    UNSIGNED_TEMPLATE = "unsigned_template_excluded"
    CODE_TEMPLATE = "code_template_excluded"


NOT_SCHEDULED_BY_QUICK_PROFILE: Final[str] = (
    QuickDisallowedReason.NOT_SCHEDULED_BY_QUICK_PROFILE.value
)

DISALLOWED_TOOL_IDS: Final[frozenset[str]] = frozenset(
    {
        "sqlmap",
        "hydra",
        "medusa",
        "clusterbomb",
        "ffuf-wordlist-full",
        "ffuf_wordlist_full",
        "impacket",
        "crackmapexec",
        "linpeas",
        "ghidra",
        "ida",
        "x64dbg",
        "gdb",
        "commix",
        "gobuster",
        "feroxbuster",
        "wfuzz",
        "dalfox",
        "xsstrike",
        "ffuf",
        "ffuf_lfi",
    }
)

_POST_EX_PHASES: Final[frozenset[str]] = frozenset(
    {"exploitation", "post_exploitation"}
)
_HEAVY_RE_FAMILIES: Final[frozenset[str]] = frozenset(
    {"reverse_engineering"}
)
_DESTRUCTIVE_RISKS: Final[frozenset[str]] = frozenset(
    {ProductionRisk.DESTRUCTIVE.value, "destructive"}
)

SKIPPED_COVERAGE_CLASSES: Final[tuple[tuple[str, str], ...]] = (
    ("quick.excluded.brute_force", NOT_SCHEDULED_BY_QUICK_PROFILE),
    ("quick.excluded.exhaustive_fuzz", NOT_SCHEDULED_BY_QUICK_PROFILE),
    ("quick.excluded.destructive", NOT_SCHEDULED_BY_QUICK_PROFILE),
    ("quick.excluded.reverse_engineering", NOT_SCHEDULED_BY_QUICK_PROFILE),
    ("quick.excluded.post_exploitation", NOT_SCHEDULED_BY_QUICK_PROFILE),
    ("quick.excluded.exploitation", NOT_SCHEDULED_BY_QUICK_PROFILE),
    ("quick.excluded.clusterbomb", NOT_SCHEDULED_BY_QUICK_PROFILE),
    ("quick.excluded.quick_fuzz", NOT_SCHEDULED_BY_QUICK_PROFILE),
)


def is_disallowed_tool(tool_id: str) -> bool:
    return str(tool_id).strip().lower() in DISALLOWED_TOOL_IDS


def allowed_tools_for_quick(node: CapabilityNode) -> tuple[str, ...]:
    """Return catalog tools that Quick may schedule for this node."""
    return tuple(tool_id for tool_id in node.tools if not is_disallowed_tool(tool_id))


def node_excluded_from_quick(node: CapabilityNode) -> bool:
    """True when the node must never appear in Quick tasks."""
    if not node.quick_eligible:
        return True
    if node.training_only:
        return True
    risk = (
        node.production_risk.value
        if isinstance(node.production_risk, ProductionRisk)
        else str(node.production_risk)
    )
    if risk in _DESTRUCTIVE_RISKS:
        return True
    family = str(node.family)
    if family in _HEAVY_RE_FAMILIES:
        return True
    phases = frozenset(str(phase) for phase in node.allowed_phases)
    return bool(phases and phases <= _POST_EX_PHASES)
