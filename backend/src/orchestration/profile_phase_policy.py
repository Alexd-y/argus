"""Profile-driven phase / budget policy (R11).

Given an immutable :class:`ResolvedScanProfile`, decide which of the 8 pipeline
phases run, which are skipped (with reasons reflected in coverage), and which
require a LAB lease preflight before running. The 8 phases themselves are
unchanged — only their *selection* is profile-driven.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from src.orchestration.phases import PHASE_ORDER, ScanPhase
from src.profiles.resolver import ResolvedScanProfile, ScanProfile

# Destructive phases require an active LAB lease (deep only).
DESTRUCTIVE_PHASES: Final[frozenset[ScanPhase]] = frozenset(
    {ScanPhase.EXPLOITATION, ScanPhase.POST_EXPLOITATION}
)

# Quick keeps a bounded, safe subset (mirrors src.quick.workflow allow-list).
_QUICK_ALLOWED: Final[frozenset[ScanPhase]] = frozenset(
    {
        ScanPhase.RECON,
        ScanPhase.THREAT_MODELING,
        ScanPhase.VULN_ANALYSIS,
        ScanPhase.REPORTING,
    }
)

_SKIP_REASON: Final[str] = "not_scheduled_by_profile"


@dataclass(frozen=True, slots=True)
class PhasePlan:
    """Resolved phase plan for a single scan (immutable)."""

    scan_profile: str
    allowed_phases: tuple[ScanPhase, ...]
    skipped: dict[ScanPhase, str]  # phase -> coverage reason code
    phase_skipping_allowed: bool
    destructive_phases_require_lease: bool
    capture_full: bool
    budget_class: str

    def is_allowed(self, phase: ScanPhase) -> bool:
        return phase in self.allowed_phases

    def requires_lease_preflight(self, phase: ScanPhase) -> bool:
        return self.destructive_phases_require_lease and phase in DESTRUCTIVE_PHASES


def plan_phases(resolved: ResolvedScanProfile) -> PhasePlan:
    """Compute the phase plan for a resolved profile (R11)."""
    profile = resolved.external_profile

    if profile is ScanProfile.QUICK:
        allowed = tuple(p for p in PHASE_ORDER if p in _QUICK_ALLOWED)
        skipped = {p: _SKIP_REASON for p in PHASE_ORDER if p not in _QUICK_ALLOWED}
        return PhasePlan(
            scan_profile=profile.value,
            allowed_phases=allowed,
            skipped=skipped,
            phase_skipping_allowed=True,
            destructive_phases_require_lease=False,
            capture_full=False,
            budget_class=resolved.budget_class,
        )

    if profile is ScanProfile.LIGHT:
        # Production-safe full web workflow; destructive phases stay out of scope.
        allowed = tuple(p for p in PHASE_ORDER if p not in DESTRUCTIVE_PHASES)
        skipped = dict.fromkeys(DESTRUCTIVE_PHASES, "out_of_scope")
        return PhasePlan(
            scan_profile=profile.value,
            allowed_phases=allowed,
            skipped=skipped,
            phase_skipping_allowed=False,
            destructive_phases_require_lease=False,
            capture_full=False,
            budget_class=resolved.budget_class,
        )

    # DEEP — full LAB workflow; destructive phases require a lease preflight.
    return PhasePlan(
        scan_profile=profile.value,
        allowed_phases=tuple(PHASE_ORDER),
        skipped={},
        phase_skipping_allowed=False,
        destructive_phases_require_lease=True,
        capture_full=True,
        budget_class=resolved.budget_class,
    )


__all__ = [
    "DESTRUCTIVE_PHASES",
    "PhasePlan",
    "plan_phases",
]
