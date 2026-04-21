"""ARG-044 — Full CISA SSVC v2.1 (deployer) decision tree.

Implements the formal **4-axis** Stakeholder-Specific Vulnerability
Categorization tree published by CISA in *SSVC: A Method to Prioritize
Remediation* (v2.1, deployer perspective). The four axes are:

1. **Exploitation** — :class:`Exploitation` (``NONE`` / ``POC`` / ``ACTIVE``).
2. **Automatable** — :class:`Automatable` (``NO`` / ``YES``).
3. **Technical Impact** — :class:`TechnicalImpact` (``PARTIAL`` / ``TOTAL``).
4. **Mission & Wellbeing** — :class:`MissionWellbeing` (``LOW`` / ``MEDIUM`` /
   ``HIGH``). The deployer tree fuses Mission Impact + Public Wellbeing
   into a single ordinal axis; we do the same to stay 1:1 with the
   reference matrix.

Cardinality: ``3 × 2 × 2 × 3 = 36`` leaves. The full lookup table is
exposed as :data:`DECISION_MATRIX` (a :class:`types.MappingProxyType`
view over a frozen dict) so callers can introspect the tree (e.g. for
the operator-facing documentation and the unit-test coverage check)
without being able to mutate it. :func:`evaluate_ssvc` is the canonical
entry point — pure, total, side-effect-free.

Public API:

* :func:`evaluate_ssvc` — the decision lookup (4 closed-enum kwargs in,
  :class:`SSVCDecision` out).
* :func:`derive_ssvc_inputs` — projects a :class:`FindingDTO` plus
  intel-tier signals (``kev_listed``, ``public_exploit_known``) into an
  :class:`SsvcInputs` record ready to feed :func:`evaluate_ssvc`.
* :data:`DECISION_MATRIX` — the immutable lookup table.
* :func:`ssvc_decide` — **legacy** 5-axis API kept for back-compat with
  Cycle 1 callers; ``exposure`` is now ignored.

Reference: https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide-508c.pdf
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING

from src.pipeline.contracts.finding_dto import (
    FindingCategory,
    SSVCDecision,
)

if TYPE_CHECKING:
    from src.pipeline.contracts.finding_dto import FindingDTO


# ---------------------------------------------------------------------------
# Axes — closed enums
# ---------------------------------------------------------------------------


class Exploitation(StrEnum):
    """Status of public exploitation evidence (CISA SSVC §3.2.1)."""

    NONE = "none"
    POC = "poc"
    ACTIVE = "active"


class Automatable(StrEnum):
    """Whether reliable exploitation can be automated (CISA SSVC §3.2.2)."""

    NO = "no"
    YES = "yes"


class TechnicalImpact(StrEnum):
    """Technical impact of successful exploitation (CISA SSVC §3.2.3)."""

    PARTIAL = "partial"
    TOTAL = "total"


class MissionWellbeing(StrEnum):
    """Combined Mission Impact + Public Wellbeing axis (CISA SSVC §3.2.4)."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# ---------------------------------------------------------------------------
# Decision matrix — verbatim from CISA SSVC v2.1 deployer tree
# ---------------------------------------------------------------------------

#: Internal mutable form, frozen behind the :data:`DECISION_MATRIX` proxy.
#: Keys are ``(exploitation, automatable, technical_impact, mission_wellbeing)``
#: tuples; values are :class:`SSVCDecision` outcomes.
_RAW_MATRIX: dict[
    tuple[Exploitation, Automatable, TechnicalImpact, MissionWellbeing],
    SSVCDecision,
] = {
    # === Exploitation: NONE ===
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.TRACK_STAR,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.ATTEND,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK_STAR,
    (Exploitation.NONE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.ATTEND,
    # === Exploitation: POC ===
    (Exploitation.POC, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.POC, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK,
    (Exploitation.POC, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.TRACK_STAR,
    (Exploitation.POC, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.POC, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK_STAR,
    (Exploitation.POC, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.ATTEND,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK_STAR,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.ATTEND,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.TRACK_STAR,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.ATTEND,
    (Exploitation.POC, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.ACT,
    # === Exploitation: ACTIVE ===
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.TRACK,
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.TRACK_STAR,
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.ATTEND,
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.TRACK_STAR,
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.ATTEND,
    (Exploitation.ACTIVE, Automatable.NO, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.ACT,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.LOW): SSVCDecision.ATTEND,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.MEDIUM): SSVCDecision.ATTEND,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.PARTIAL, MissionWellbeing.HIGH): SSVCDecision.ACT,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.LOW): SSVCDecision.ATTEND,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.MEDIUM): SSVCDecision.ACT,
    (Exploitation.ACTIVE, Automatable.YES, TechnicalImpact.TOTAL, MissionWellbeing.HIGH): SSVCDecision.ACT,
}

#: Frozen view over :data:`_RAW_MATRIX` — safe to expose to callers.
DECISION_MATRIX: MappingProxyType[
    tuple[Exploitation, Automatable, TechnicalImpact, MissionWellbeing],
    SSVCDecision,
] = MappingProxyType(_RAW_MATRIX)


# ---------------------------------------------------------------------------
# Public dataclass — input bundle
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SsvcInputs:
    """Bundle of the four CISA SSVC axes for a single finding."""

    exploitation: Exploitation
    automatable: Automatable
    technical_impact: TechnicalImpact
    mission_wellbeing: MissionWellbeing


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def evaluate_ssvc(
    *,
    exploitation: Exploitation,
    automatable: Automatable,
    technical_impact: TechnicalImpact,
    mission_wellbeing: MissionWellbeing,
) -> SSVCDecision:
    """Return the CISA SSVC decision for the supplied 4-axis profile.

    The function is a pure dictionary lookup against :data:`DECISION_MATRIX`.
    All four arguments are closed enums; mypy enforces the call site, the
    runtime guard is a defensive ``KeyError`` fallback that returns
    :attr:`SSVCDecision.TRACK` (the safe default) instead of crashing.
    """
    key = (exploitation, automatable, technical_impact, mission_wellbeing)
    try:
        return DECISION_MATRIX[key]
    except KeyError:  # pragma: no cover — closed-enum invariant
        return SSVCDecision.TRACK


def derive_ssvc_inputs(
    finding: "FindingDTO",
    *,
    kev_listed: bool,
    public_exploit_known: bool,
    mission_wellbeing: MissionWellbeing | None = None,
) -> SsvcInputs:
    """Project a :class:`FindingDTO` + intel signals into :class:`SsvcInputs`.

    The mapping rules are deliberately conservative — when in doubt we
    bias *away* from over-escalation:

    * **Exploitation.** ``kev_listed → ACTIVE`` (CISA marks a CVE in the
      KEV catalog as actively exploited by definition); else
      ``public_exploit_known → POC``; else ``NONE``.
    * **Automatable.** Categories that historically ship with weaponised
      mass-scan tooling (``RCE``, ``SQLI``, ``SSRF``, ``CMDI``, ``LFI``,
      ``XXE``, ``OPEN_REDIRECT`` chains, ``IDOR``) → ``YES``. Everything
      else → ``NO``. The list mirrors the CISA SSVC §3.2.2 guidance for
      "remote, no auth, no special config".
    * **Technical Impact.** ``cvss_v3_score >= 7.0`` → ``TOTAL`` (CVSS
      "High" / "Critical"); else ``PARTIAL``.
    * **Mission Wellbeing.** Caller-supplied (asset-criticality is the
      asset module's responsibility, not the finding module's). Default
      :attr:`MissionWellbeing.MEDIUM` keeps deployments without an
      asset-criticality model on the safe side of the matrix.
    """
    if kev_listed:
        exploitation = Exploitation.ACTIVE
    elif public_exploit_known:
        exploitation = Exploitation.POC
    else:
        exploitation = Exploitation.NONE

    automatable = (
        Automatable.YES if finding.category in _AUTOMATABLE_CATEGORIES else Automatable.NO
    )

    technical_impact = (
        TechnicalImpact.TOTAL
        if finding.cvss_v3_score >= 7.0
        else TechnicalImpact.PARTIAL
    )

    return SsvcInputs(
        exploitation=exploitation,
        automatable=automatable,
        technical_impact=technical_impact,
        mission_wellbeing=mission_wellbeing or MissionWellbeing.MEDIUM,
    )


# ---------------------------------------------------------------------------
# Backwards-compatible legacy API (Cycle 1)
# ---------------------------------------------------------------------------

# Re-export the legacy enum names so existing imports keep working.
SSVCExploitation = Exploitation
SSVCTechnicalImpact = TechnicalImpact
SSVCMissionImpact = MissionWellbeing


class SSVCExposure(StrEnum):
    """Legacy axis (CISA dropped Exposure from the deployer tree in v2.1).

    Kept as a closed enum so old call sites still type-check; the value
    is no longer read by :func:`ssvc_decide` (matrix lookup ignores it).
    """

    SMALL = "small"
    CONTROLLED = "controlled"
    OPEN = "open"


def ssvc_decide(
    *,
    exploitation: SSVCExploitation,
    exposure: SSVCExposure,  # noqa: ARG001 — kept for back-compat
    automatable: bool,
    technical_impact: SSVCTechnicalImpact,
    mission_well_being: SSVCMissionImpact,
) -> SSVCDecision:
    """Legacy entry point — delegates to :func:`evaluate_ssvc`.

    The ``exposure`` argument is accepted but ignored: CISA SSVC v2.1
    deployer tree no longer takes Exposure as a primary axis. New code
    should call :func:`evaluate_ssvc` directly.
    """
    return evaluate_ssvc(
        exploitation=exploitation,
        automatable=Automatable.YES if automatable else Automatable.NO,
        technical_impact=technical_impact,
        mission_wellbeing=mission_well_being,
    )


# ---------------------------------------------------------------------------
# Module-private constants
# ---------------------------------------------------------------------------

#: Categories with reliable mass-exploitation tooling (CISA SSVC §3.2.2).
_AUTOMATABLE_CATEGORIES: frozenset[FindingCategory] = frozenset(
    {
        FindingCategory.RCE,
        FindingCategory.SQLI,
        FindingCategory.SSRF,
        FindingCategory.CMDI,
        FindingCategory.LFI,
        FindingCategory.XXE,
        FindingCategory.SSTI,
        FindingCategory.NOSQLI,
        FindingCategory.LDAPI,
        FindingCategory.IDOR,
        FindingCategory.OPEN_REDIRECT,
        FindingCategory.JWT,
    }
)


__all__ = [
    "DECISION_MATRIX",
    "Automatable",
    "Exploitation",
    "MissionWellbeing",
    "SSVCDecision",
    "SSVCExploitation",
    "SSVCExposure",
    "SSVCMissionImpact",
    "SSVCTechnicalImpact",
    "SsvcInputs",
    "TechnicalImpact",
    "derive_ssvc_inputs",
    "evaluate_ssvc",
    "ssvc_decide",
]
