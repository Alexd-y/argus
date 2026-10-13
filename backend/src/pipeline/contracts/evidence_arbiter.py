"""Artifact-driven evidence-tier arbiter (R-5.1.2, R-5.1.6).

This module is the **only** sanctioned way to decide a finding's
:class:`~src.pipeline.contracts.finding_dto.EvidenceTier`. :func:`adjudicate`
takes the set of *actually collected* artifacts (:class:`EvidenceDTO`) and
returns the tier they justify, together with machine-readable reasons for why
the tier is not higher.

Why this exists
---------------
Historically the tier was derived from ``ConfidenceLevel`` — a *self-assessment
by the language model* — via ``classify_finding``. A model that called a finding
"exploitable" was handed ``CONFIRMED`` with zero collected evidence. This module
inverts that: the tier is a function of collected artifacts and nothing else.

``ConfidenceLevel`` (and any other model judgement) is deliberately **not** a
parameter of :func:`adjudicate` — there is no input through which a language
model's opinion can lift the tier. That is R-5.1.6 expressed as a signature.

Wave-1 scope
------------
Only requirements provable from the artifacts that exist today are enforced.
The mandatory negative control (R-5.4.x) and the repeatability confirmation
(R-5.5.x) arrive in wave 3. Their slots are reserved here now
(:class:`EvidenceRequirement`, :class:`DowngradeReason`) and **every** verdict
honestly records that they were *not checked yet*, so the arbiter never
silently implies a guarantee it cannot back. Wiring wave 3 is then a localized
change: turn those "pending" reasons into real tier caps.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from src.pipeline.contracts.finding_dto import EvidenceDTO, EvidenceKind, EvidenceTier


class EvidenceRequirement(StrEnum):
    """A condition on the collected artifacts that can lift the tier."""

    #: A full request/response exchange with the target is saved.
    RAW_EXCHANGE = "raw_exchange"
    #: An artifact recording an achieved effect of the interaction.
    IMPACT_PROOF = "impact_proof"
    #: Reserved — negative control on a benign input (wave 3, R-5.4.x).
    NEGATIVE_CONTROL = "negative_control"
    #: Reserved — observation reproduced ≥2 times (wave 3, R-5.5.x).
    REPEATABILITY = "repeatability"


class DowngradeReason(StrEnum):
    """Machine-readable reason a verdict is not a higher tier."""

    NO_ARTIFACTS = "no_artifacts"
    NO_RAW_EXCHANGE = "no_raw_exchange"
    NO_IMPACT_PROOF = "no_impact_proof"
    #: Recorded when a wave-3 gate's input was not supplied by the caller (an
    #: unwired path) — keeps a tier at/above CONFIRMED honest about what was not
    #: verified. A caller that DOES supply the input gets the real gate reason
    #: below instead.
    NEGATIVE_CONTROL_NOT_CHECKED = "negative_control_not_checked"
    REPEATABILITY_NOT_CHECKED = "repeatability_not_checked"
    #: Wave-3 gates, enforced when the caller supplies the input (R-5.4/5.5).
    NEGATIVE_CONTROL_MISSING = "negative_control_missing"
    REPEATABILITY_MISSING = "repeatability_not_confirmed"
    REPEATABILITY_DIVERGED = "repeatability_diverged"
    INTERFERENCE_OBSERVED = "interference_observed"


@dataclass(frozen=True)
class RepeatabilityOutcome:
    """Result of re-running an observation (R-5.5). ``required`` runs must all
    match for a CONFIRMED-or-higher tier to stand."""

    attempts: int
    matched: int
    required: int = 2

    @property
    def confirmed(self) -> bool:
        return self.attempts >= self.required and self.matched >= self.attempts

    @property
    def diverged(self) -> bool:
        # Ran enough times but at least one run disagreed — unstable behaviour.
        return self.attempts >= 2 and self.matched < self.attempts


# --- Which EvidenceKind satisfies which requirement --------------------------
#
# Conservative on purpose. ``RAW_OUTPUT`` / ``PARSED`` / ``DIFF`` are *an*
# artifact but do NOT, on their own, prove a request/response exchange with the
# target. Treating raw tool stdout as a "raw exchange" would make every tool run
# CONFIRMED once wave 2 registers a ``RAW_OUTPUT`` for every run (R-5.3.1),
# which would defeat the entire honesty goal of this work. Only genuine
# request/response captures (HAR) and packet captures (PCAP) count as a raw
# exchange here.
_RAW_EXCHANGE_KINDS: frozenset[EvidenceKind] = frozenset({EvidenceKind.HAR, EvidenceKind.PCAP})
#: Kinds that record an achieved effect of the interaction (out-of-band
#: callback, a captured visual effect, a recording).
_IMPACT_PROOF_KINDS: frozenset[EvidenceKind] = frozenset(
    {EvidenceKind.SCREENSHOT, EvidenceKind.OAST_CALLBACK, EvidenceKind.VIDEO}
)

#: Gates that do not exist before wave 3 — always recorded as "not checked".
_WAVE3_PENDING: tuple[DowngradeReason, ...] = (
    DowngradeReason.NEGATIVE_CONTROL_NOT_CHECKED,
    DowngradeReason.REPEATABILITY_NOT_CHECKED,
)


@dataclass(frozen=True)
class ArbiterVerdict:
    """The tier justified by a set of artifacts, plus why it is not higher."""

    tier: EvidenceTier
    #: Ordered reasons the tier is not higher (machine-readable, for the report).
    reasons: tuple[DowngradeReason, ...]
    #: Requirements the supplied artifacts satisfy.
    satisfied: frozenset[EvidenceRequirement]


def _cap(tier: EvidenceTier, ceiling: EvidenceTier) -> EvidenceTier:
    """Lower ``tier`` to ``ceiling`` if it is higher (a cap never raises)."""
    return EvidenceTier(min(int(tier), int(ceiling)))


def adjudicate(
    *,
    artifacts: Sequence[EvidenceDTO],
    vuln_class: str | None = None,  # noqa: ARG001 — reserved for signed per-class policy
    negative_control_required: bool = False,
    negative_control_present: bool = False,
    repeatability: RepeatabilityOutcome | None = None,
    interference: bool = False,
) -> ArbiterVerdict:
    """Return the :class:`EvidenceTier` justified by ``artifacts`` and the
    wave-3 gates.

    Base rules (wave 1), from the artifacts alone:

    * ``EXPLOITED``      — a raw exchange *and* an impact-proof artifact.
    * ``CONFIRMED``      — a raw exchange (request+response) is saved.
    * ``SUSPECTED``      — some artifact exists, but no raw exchange.
    * ``INFORMATIONAL``  — no artifacts at all.

    Wave-3 gates then only ever LOWER the tier (R-5.4/5.5):

    * **Negative control** — when ``negative_control_required`` (a per-class
      policy decided by the caller) and it is not present, the tier is capped at
      ``SUSPECTED``.
    * **Repeatability** — when a :class:`RepeatabilityOutcome` is supplied and
      the observation did not reproduce (or diverged across runs), the tier is
      capped at ``SUSPECTED``; divergence is recorded, not discarded.
    * **Interference** — a tripped WAF / rate-limit / target-unreachable /
      fingerprint-change signal caps the tier at ``SUSPECTED`` (limited
      observability).

    A gate whose input the caller does not supply records a "not checked" reason
    (and does not cap), so an unwired path keeps the wave-1 behaviour and stays
    honest. No parameter carries a language-model judgement.
    """
    if not artifacts:
        return ArbiterVerdict(
            tier=EvidenceTier.INFORMATIONAL,
            reasons=(DowngradeReason.NO_ARTIFACTS, *_WAVE3_PENDING),
            satisfied=frozenset(),
        )

    kinds = {artifact.kind for artifact in artifacts}
    has_raw = bool(kinds & _RAW_EXCHANGE_KINDS)
    has_impact = bool(kinds & _IMPACT_PROOF_KINDS)

    satisfied: set[EvidenceRequirement] = set()
    if has_raw:
        satisfied.add(EvidenceRequirement.RAW_EXCHANGE)
    if has_impact:
        satisfied.add(EvidenceRequirement.IMPACT_PROOF)

    reasons: list[DowngradeReason] = []
    if has_raw and has_impact:
        tier = EvidenceTier.EXPLOITED
    elif has_raw:
        tier = EvidenceTier.CONFIRMED
        reasons.append(DowngradeReason.NO_IMPACT_PROOF)
    else:
        tier = EvidenceTier.SUSPECTED
        reasons.append(DowngradeReason.NO_RAW_EXCHANGE)

    _ceil = EvidenceTier.SUSPECTED

    # --- Negative control (R-5.4) ---
    if negative_control_required:
        if negative_control_present:
            satisfied.add(EvidenceRequirement.NEGATIVE_CONTROL)
        else:
            tier = _cap(tier, _ceil)
            reasons.append(DowngradeReason.NEGATIVE_CONTROL_MISSING)
    else:
        reasons.append(DowngradeReason.NEGATIVE_CONTROL_NOT_CHECKED)

    # --- Repeatability (R-5.5) ---
    if repeatability is not None:
        if repeatability.confirmed:
            satisfied.add(EvidenceRequirement.REPEATABILITY)
        elif repeatability.diverged:
            tier = _cap(tier, _ceil)
            reasons.append(DowngradeReason.REPEATABILITY_DIVERGED)
        else:
            tier = _cap(tier, _ceil)
            reasons.append(DowngradeReason.REPEATABILITY_MISSING)
    else:
        reasons.append(DowngradeReason.REPEATABILITY_NOT_CHECKED)

    # --- Interference (R-5.5.3) ---
    if interference:
        tier = _cap(tier, _ceil)
        reasons.append(DowngradeReason.INTERFERENCE_OBSERVED)

    return ArbiterVerdict(
        tier=tier,
        reasons=tuple(reasons),
        satisfied=frozenset(satisfied),
    )


__all__ = [
    "ArbiterVerdict",
    "DowngradeReason",
    "EvidenceRequirement",
    "RepeatabilityOutcome",
    "adjudicate",
]
