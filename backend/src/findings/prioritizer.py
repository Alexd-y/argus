"""Compound priority scoring + ranking for :class:`FindingDTO`.

Two complementary surfaces live in this module:

* :class:`Prioritizer` — Cycle 1 weighted-sum scorer producing a
  numerical 0-100 :class:`PriorityScore` plus a discrete P0-P4 tier.
  Used by the API + report layer to render "why this finding ranked
  P0" in the UI breakdown.
* :class:`FindingPrioritizer` (ARG-044) — deterministic *ordinal*
  ranker producing a stable, lexicographic ordering. Used by the
  Valhalla executive renderer and any other consumer that needs a
  predictable "top N" list independent of floating-point noise.

The two surfaces deliberately share the SSVC decision input but draw
different conclusions:

* :class:`Prioritizer` interpolates a number — comparable across runs
  but sensitive to weight tuning.
* :class:`FindingPrioritizer` short-circuits on the strongest signal
  available (``KEV listed`` first, then SSVC tier, CVSSv3 score, EPSS
  percentile, then a stable tie-breaker on the finding UUID). This is
  the algorithm the operator sees in the executive report.

Both classes are pure (no I/O, no global state) and idempotent; ranking
the same input twice returns the exact same order.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, StrictFloat

from src.pipeline.contracts.finding_dto import FindingDTO, SSVCDecision


@runtime_checkable
class _RankableFinding(Protocol):
    """Duck-typed surface used by :class:`FindingPrioritizer`.

    Both :class:`FindingDTO` and :class:`src.api.schemas.Finding` (after
    ARG-044 expansion) satisfy this protocol; introducing it keeps the
    prioritiser layer-agnostic so the report renderer can rank API
    objects without round-tripping through a DTO conversion.
    """

    @property
    def kev_listed(self) -> bool: ...
    @property
    def ssvc_decision(self) -> Any: ...
    @property
    def epss_score(self) -> float | None: ...
    @property
    def epss_percentile(self) -> float | None: ...


class PriorityComponent(StrEnum):
    """Signal contributing to a :class:`PriorityScore`."""

    CVSS = "cvss"
    EPSS = "epss"
    KEV = "kev"
    SSVC = "ssvc"


class PriorityTier(StrEnum):
    """Discrete prioritisation tier (Backlog/dev1_md §11)."""

    P0_CRITICAL = "P0_CRITICAL"
    P1_HIGH = "P1_HIGH"
    P2_MEDIUM = "P2_MEDIUM"
    P3_LOW = "P3_LOW"
    P4_INFO = "P4_INFO"


_SSVC_WEIGHT: Final[dict[SSVCDecision, float]] = {
    SSVCDecision.ACT: 100.0,
    SSVCDecision.ATTEND: 75.0,
    SSVCDecision.TRACK_STAR: 50.0,
    SSVCDecision.TRACK: 25.0,
}

# Weights add to 1.0; component max contributions are 40 / 25 / 20 / 15 = 100.
_W_CVSS: Final[float] = 0.4
_W_EPSS: Final[float] = 0.25
_W_KEV: Final[float] = 0.2
_W_SSVC: Final[float] = 0.15

_TIER_THRESHOLDS: Final[tuple[tuple[float, PriorityTier], ...]] = (
    (90.0, PriorityTier.P0_CRITICAL),
    (70.0, PriorityTier.P1_HIGH),
    (40.0, PriorityTier.P2_MEDIUM),
    (20.0, PriorityTier.P3_LOW),
)


class PriorityScore(BaseModel):
    """Numerical + categorical priority output for a single finding."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    score: StrictFloat = Field(ge=0.0, le=100.0)
    breakdown: dict[PriorityComponent, StrictFloat]
    tier: PriorityTier


class Prioritizer:
    """Pure transform from :class:`FindingDTO` to :class:`PriorityScore`."""

    def prioritize(self, finding: FindingDTO) -> PriorityScore:
        """Compute the priority score and tier for ``finding``."""
        cvss_part = _component_cvss(finding.cvss_v3_score)
        epss_part = _component_epss(finding.epss_score)
        kev_part = _component_kev(finding.kev_listed)
        ssvc_part = _component_ssvc(finding.ssvc_decision)

        total = cvss_part + epss_part + kev_part + ssvc_part
        clamped = max(0.0, min(100.0, total))

        breakdown: dict[PriorityComponent, float] = {
            PriorityComponent.CVSS: round(cvss_part, 4),
            PriorityComponent.EPSS: round(epss_part, 4),
            PriorityComponent.KEV: round(kev_part, 4),
            PriorityComponent.SSVC: round(ssvc_part, 4),
        }
        return PriorityScore(
            score=round(clamped, 4),
            breakdown=breakdown,
            tier=_tier_for(clamped),
        )


def _component_cvss(cvss_score: float) -> float:
    """CVSS base contribution to the 0-100 priority score; max ``40``.

    The CVSS v3 base score is on a 0-10 scale, but the priority weight
    table normalises every component to a 0-100 sub-score before applying
    its weight (``_W_CVSS = 0.4`` ⇒ max 40). The ``× 10`` multiplier
    therefore re-scales CVSS to the same 0-100 unit as EPSS / KEV / SSVC,
    keeping the four components additive on a single scale. For example,
    a perfect 10.0 CVSS contributes ``0.4 × (10.0 × 10) = 40``, matching
    the documented cap. Without the ``× 10`` factor the CVSS axis would
    silently account for only 4/100 instead of the 40/100 documented in
    Backlog/dev1_md §11.
    """
    if cvss_score < 0.0:
        return 0.0
    capped = min(cvss_score, 10.0)
    return _W_CVSS * capped * 10.0


def _component_epss(epss: float | None) -> float:
    """EPSS contribution; max 25 (epss=1.0). ``None`` ⇒ 0."""
    if epss is None:
        return 0.0
    if epss < 0.0:
        return 0.0
    capped = min(epss, 1.0)
    return _W_EPSS * capped * 100.0


def _component_kev(kev_listed: bool) -> float:
    """KEV contribution; 20 if listed, else 0."""
    return _W_KEV * 100.0 if kev_listed else 0.0


def _component_ssvc(decision: SSVCDecision) -> float:
    """SSVC contribution; max 15 (ACT)."""
    weight = _SSVC_WEIGHT.get(decision, 0.0)
    return _W_SSVC * weight


def _tier_for(score: float) -> PriorityTier:
    """Map a 0-100 score to the discrete tier."""
    for threshold, tier in _TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return PriorityTier.P4_INFO


# ---------------------------------------------------------------------------
# ARG-044 — Deterministic ordinal ranker
# ---------------------------------------------------------------------------


#: Ordering of SSVC decisions for the deterministic rank: ACT > ATTEND >
#: TRACK_STAR > TRACK. Higher value = higher priority.
_SSVC_RANK: Final[dict[SSVCDecision, int]] = {
    SSVCDecision.ACT: 4,
    SSVCDecision.ATTEND: 3,
    SSVCDecision.TRACK_STAR: 2,
    SSVCDecision.TRACK: 1,
}


@dataclass(frozen=True, slots=True)
class RankedFinding:
    """A :class:`FindingDTO` paired with its computed sort key.

    The :attr:`rank_key` is exposed so callers can introspect the exact
    tuple that drove the ordering — useful for "why is this finding ranked
    above that one?" debugging in the operator UI.
    """

    finding: FindingDTO
    rank_key: tuple[int, int, float, float, str]


class FindingPrioritizer:
    """Deterministic ordinal ranker for :class:`FindingDTO` collections.

    Tie-break order (descending priority):

    1. ``KEV listed`` — actively exploited per CISA.
    2. ``SSVC decision`` (Act > Attend > Track* > Track).
    3. ``CVSSv3 base score`` (higher first).
    4. ``EPSS percentile`` (higher first).
    5. Stable hash of the finding ``id`` — guarantees a total order even
       when every other signal ties (e.g. two RCE findings against the
       same asset with identical CVSS).

    The returned ordering is **strictly deterministic**: given the same
    multiset of findings, the order is identical across processes and
    runs. This is the contract the Valhalla executive renderer relies on
    so report diffs across re-runs are noise-free.
    """

    @staticmethod
    def rank_findings(
        findings: Iterable[FindingDTO],
    ) -> list[FindingDTO]:
        """Return ``findings`` in priority-descending order."""
        ranked = FindingPrioritizer.rank_findings_with_keys(findings)
        return [rf.finding for rf in ranked]

    @staticmethod
    def rank_findings_with_keys(
        findings: Iterable[FindingDTO],
    ) -> list[RankedFinding]:
        """Return :class:`RankedFinding` records in priority-descending order."""
        decorated = [
            RankedFinding(finding=f, rank_key=_compute_rank_key(f))
            for f in findings
        ]
        # Negate numeric fields so descending sort = highest priority first;
        # the hash tie-breaker stays ascending so the result is stable.
        decorated.sort(
            key=lambda rf: (
                -rf.rank_key[0],
                -rf.rank_key[1],
                -rf.rank_key[2],
                -rf.rank_key[3],
                rf.rank_key[4],
            )
        )
        return decorated

    @staticmethod
    def top_n(
        findings: Sequence[FindingDTO],
        n: int,
    ) -> list[FindingDTO]:
        """Return the highest-priority ``n`` findings (deterministic)."""
        if n <= 0:
            return []
        return FindingPrioritizer.rank_findings(findings)[:n]

    @staticmethod
    def rank_objects(
        findings: Sequence[Any],
        *,
        id_extractor: callable | None = None,  # type: ignore[valid-type]
    ) -> list[Any]:
        """Rank duck-typed finding objects (``Finding`` API schema, etc.).

        Used by the Valhalla executive renderer which works on the API
        :class:`Finding` model rather than the DTO. ``id_extractor`` is
        an optional callable returning a stable identifier (string) for
        the finding — defaults to using the object's ``title``+``cwe``
        composite when no identifier attribute is present (typical for
        :class:`Finding` which has no ``id`` field of its own).
        """
        if id_extractor is None:

            def _default_id(o: Any) -> str:
                # Prefer real identifiers when present (DTOs, ORM rows).
                for attr in ("id", "finding_id", "uuid"):
                    val = getattr(o, attr, None)
                    if val is not None:
                        return str(val)
                # Fallback: title|cwe — stable across runs of the same
                # report data because both are deterministic outputs of
                # the upstream normaliser.
                title = getattr(o, "title", "") or ""
                cwe = getattr(o, "cwe", "") or ""
                return f"{title}|{cwe}"

            id_extractor = _default_id

        decorated: list[tuple[tuple[int, int, float, float, str], Any]] = []
        for f in findings:
            key = _compute_rank_key_duck(f, id_extractor(f))
            decorated.append((key, f))
        decorated.sort(
            key=lambda pair: (
                -pair[0][0],
                -pair[0][1],
                -pair[0][2],
                -pair[0][3],
                pair[0][4],
            )
        )
        return [pair[1] for pair in decorated]


def _compute_rank_key(
    finding: FindingDTO,
) -> tuple[int, int, float, float, str]:
    """Build the lexicographic sort key for a single finding.

    Tuple shape: ``(kev, ssvc, cvss, epss_percentile, id_hash)``.
    """
    kev = 1 if finding.kev_listed else 0
    ssvc = _SSVC_RANK.get(finding.ssvc_decision, 0)
    cvss = float(finding.cvss_v3_score or 0.0)
    # EPSS percentile (0..1) is the primary intel signal; fall back to
    # the raw EPSS score, then 0 — never None — so sort comparisons stay
    # total even with mixed enrichment coverage.
    if finding.epss_percentile is not None:
        epss = float(finding.epss_percentile)
    elif finding.epss_score is not None:
        epss = float(finding.epss_score)
    else:
        epss = 0.0
    id_hash = _stable_id_hash(finding.id)
    return (kev, ssvc, cvss, epss, id_hash)


def _compute_rank_key_duck(
    finding: Any,
    stable_id: str,
) -> tuple[int, int, float, float, str]:
    """Build the rank key for a duck-typed finding object.

    Mirrors :func:`_compute_rank_key` but reads via ``getattr`` so any
    object satisfying :class:`_RankableFinding` (including the API
    :class:`src.api.schemas.Finding` model) can be ranked.
    """
    kev = 1 if bool(getattr(finding, "kev_listed", False)) else 0

    raw_ssvc = getattr(finding, "ssvc_decision", None)
    ssvc = 0
    if isinstance(raw_ssvc, SSVCDecision):
        ssvc = _SSVC_RANK.get(raw_ssvc, 0)
    elif isinstance(raw_ssvc, str):
        try:
            ssvc = _SSVC_RANK.get(SSVCDecision(raw_ssvc), 0)
        except ValueError:
            ssvc = 0

    cvss_raw = getattr(finding, "cvss_v3_score", None)
    if cvss_raw is None:
        cvss_raw = getattr(finding, "cvss", None)
    cvss = float(cvss_raw) if cvss_raw is not None else 0.0

    pct = getattr(finding, "epss_percentile", None)
    score = getattr(finding, "epss_score", None)
    if pct is not None:
        epss = float(pct)
    elif score is not None:
        epss = float(score)
    else:
        epss = 0.0

    return (
        kev,
        ssvc,
        cvss,
        epss,
        hashlib.sha256(stable_id.encode("utf-8")).hexdigest()[:16],
    )


def _stable_id_hash(finding_id: UUID) -> str:
    """Stable, content-derived 16-char hex hash of the finding UUID.

    We deliberately do *not* use the UUID's natural string ordering for
    the tie-breaker — UUID v4 buckets have time-correlated bias which
    would let an attacker influence ranking by controlling the finding
    creation timestamp. ``sha256`` is overkill for the use case but
    cheap and removes any speculation about the property.
    """
    return hashlib.sha256(finding_id.bytes).hexdigest()[:16]


__all__ = [
    "FindingPrioritizer",
    "Prioritizer",
    "PriorityComponent",
    "PriorityScore",
    "PriorityTier",
    "RankedFinding",
]
