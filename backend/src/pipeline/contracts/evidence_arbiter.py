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
    #: Reserved gates not implemented until wave 3 — recorded on every verdict
    #: so a tier at/above CONFIRMED stays honest about what was not verified.
    NEGATIVE_CONTROL_NOT_CHECKED = "negative_control_not_checked_wave3"
    REPEATABILITY_NOT_CHECKED = "repeatability_not_checked_wave3"


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


def adjudicate(
    *,
    artifacts: Sequence[EvidenceDTO],
    # vuln_class: reserved for the signed per-class policy (wave 3, R-5.4.1).
    vuln_class: str | None = None,  # noqa: ARG001
) -> ArbiterVerdict:
    """Return the :class:`EvidenceTier` justified by ``artifacts`` alone.

    Rules (wave 1):

    * ``EXPLOITED``      — a raw exchange *and* an impact-proof artifact.
    * ``CONFIRMED``      — a raw exchange (request+response) is saved.
    * ``SUSPECTED``      — some artifact exists, but no raw exchange.
    * ``INFORMATIONAL``  — no artifacts at all.

    ``vuln_class`` is accepted for forward-compatibility (a signed per-class
    policy of which classes can even be proven exploitable lands in a later
    wave, R-5.4.1). It never *raises* the tier in wave 1.

    No parameter carries a language-model judgement: with an empty
    ``artifacts`` sequence the result is ``INFORMATIONAL`` regardless of any
    other input, which is R-5.1.6 in executable form.
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

    # Negative control + repeatability are not verifiable until wave 3; record
    # that honestly on every verdict so the tier never over-claims.
    reasons.extend(_WAVE3_PENDING)

    return ArbiterVerdict(
        tier=tier,
        reasons=tuple(reasons),
        satisfied=frozenset(satisfied),
    )


__all__ = [
    "ArbiterVerdict",
    "DowngradeReason",
    "EvidenceRequirement",
    "adjudicate",
]
