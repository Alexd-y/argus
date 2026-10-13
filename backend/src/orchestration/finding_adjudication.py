"""Production entry to the evidence arbiter for finding dicts (R-5.1.2, wave 3 etap 4b).

This is the single sanctioned place that turns a finding's *collected artifacts*
(as recorded in its ``proof_of_concept``) into an :class:`EvidenceTier` via
:func:`src.pipeline.contracts.evidence_arbiter.adjudicate`, replacing the tier
that was derived from the language model's self-assessed confidence
(``classify_finding``). The per-class confirmation rules in
:mod:`src.reports.poc_validation` are folded in as the arbiter's ``class_confirmed``
gate, so there is **one** source of truth, not two parallel downgrade paths.

Safety contract — why this cannot wreck a scan's findings
---------------------------------------------------------
* **Cap-only.** The arbiter verdict is only ever applied as a *cap*: the final
  tier is ``min(model_tier, arbiter_tier)``. The arbiter can demote a tier the
  artifacts do not justify; it never *raises* a tier (a raise would re-introduce
  the "assert it and it's true" hole wave 3 closes). The honest worst case is an
  under-rated finding, never an over-claimed one.
* **In-domain only.** A finding is adjudicated only when the arbiter actually
  has visibility into it — it carries stored artifact keys OR resolves to a
  confirmation class. Heuristic findings outside the HTTP/PoC evidence model
  (fuzzer crashes, binary-analysis hits) have no artifact keys and no class;
  they are returned **unchanged** so their locally-justified tier survives.
* **Genuine artifacts only.** A raw-exchange kind (HAR/PCAP) is counted only
  when its PoC key is a real content-addressed object key
  (``{kind}-{sha256[:16]}.bin``) — a hallucinated ``har_evidence_key: "foo"``
  does not match and cannot lift the tier.

``repeatability`` and ``interference`` are not collected per-finding at this
site yet, so they are passed as "not checked"; the arbiter records that
honestly and does not cap on them here.

Import note: :mod:`src.reports.poc_validation` lives under the heavy ``reports``
package (WeasyPrint et al.), so it is imported lazily inside the function — this
module must be importable at backend boot without dragging in the report stack.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from src.pipeline.contracts.evidence_arbiter import ArbiterVerdict, adjudicate
from src.pipeline.contracts.finding_dto import EvidenceKind

#: Confirmation-class *values* whose rule mandates a negative control
#: (poc_validation ``_rule_idor`` / ``_rule_auth_bypass``). Stored as strings so
#: this module need not import the ConfirmationClass enum at load time. For these
#: classes a missing negative control caps the tier at SUSPECTED (R-5.4).
_NEGATIVE_CONTROL_CLASS_VALUES: frozenset[str] = frozenset({"idor", "bola", "auth_bypass"})

#: A genuine content-addressed evidence object key ends in ``{kind}-{hex}.bin``
#: (``EvidencePipeline._prepare`` → ``f"{kind.value}-{sha256[:16]}.bin"``). We
#: match the basename so any storage prefix is tolerated.
_CONTENT_ADDRESSED = re.compile(r"(?:^|/)(har|pcap)-[0-9a-f]{16,64}\.bin$")


@dataclass(frozen=True)
class FindingAdjudication:
    """Outcome of adjudicating one finding's tier."""

    #: The tier to persist (capped). Equals the model tier when not applicable.
    tier: int | None
    #: Whether the arbiter had visibility into this finding (artifacts or class).
    applicable: bool
    #: The model-assigned tier that was fed in (for shadow/audit logging).
    model_tier: int | None
    #: The arbiter's verdict, or None when not applicable.
    verdict: ArbiterVerdict | None
    #: Machine-readable reasons the tier is not higher (empty when not applicable).
    reasons: tuple[str, ...]

    @property
    def arbiter_tier(self) -> int | None:
        return int(self.verdict.tier) if self.verdict is not None else None


def _coerce_tier(value: Any) -> int | None:
    """Return a valid 1..4 tier int, or None."""
    if isinstance(value, bool):  # bool is an int subclass — reject explicitly.
        return None
    if isinstance(value, (int, float)) and 1 <= int(value) <= 4:
        return int(value)
    return None


def _present_kinds(poc_outer: dict[str, Any], root: dict[str, Any]) -> frozenset[EvidenceKind]:
    """Evidence kinds for which this finding genuinely stored an artifact.

    HAR/PCAP (the raw-exchange kinds that justify CONFIRMED) are counted only
    when their key is a real content-addressed object key; screenshot/video
    (impact proof) are counted on any non-empty key — under the cap-only rule an
    impact-proof kind can never inflate a tier on its own.
    """
    kinds: set[EvidenceKind] = set()

    def _str(*keys: str) -> str:
        for container in (poc_outer, root):
            for key in keys:
                val = container.get(key)
                if isinstance(val, str) and val.strip():
                    return val.strip()
        return ""

    har = _str("har_evidence_key", "har_key", "har")
    if har and _CONTENT_ADDRESSED.search(har):
        kinds.add(EvidenceKind.HAR)
    pcap = _str("pcap_evidence_key", "pcap_key", "pcap")
    if pcap and _CONTENT_ADDRESSED.search(pcap):
        kinds.add(EvidenceKind.PCAP)
    if _str("screenshot_key", "screenshot_evidence_key", "screenshot"):
        kinds.add(EvidenceKind.SCREENSHOT)
    if _str("video_key", "video_evidence_key", "video"):
        kinds.add(EvidenceKind.VIDEO)
    return frozenset(kinds)


def adjudicate_finding_tier(finding: dict[str, Any]) -> FindingAdjudication:
    """Adjudicate one finding dict's :class:`EvidenceTier` from its collected
    artifacts and the wave-3 gates.

    Returns a :class:`FindingAdjudication`. When the finding is outside the
    arbiter's visibility (no stored artifact keys and no resolvable class) the
    result is ``applicable=False`` and ``tier`` is the unchanged model tier.
    """
    # Lazy import — keep this module importable at boot without the report stack.
    from src.reports.poc_validation import (
        _negative_control_value,
        _poc_root,
        evaluate_class_confirmation,
        resolve_confirmation_class,
    )

    model_tier = _coerce_tier(finding.get("evidence_tier"))

    poc_outer = finding.get("proof_of_concept")
    poc_outer = poc_outer if isinstance(poc_outer, dict) else {}
    root = _poc_root(poc_outer) if poc_outer else {}

    present = _present_kinds(poc_outer, root)
    parts = [
        str(finding.get(key) or "")
        for key in ("title", "name", "cwe", "owasp_category", "vuln_type", "category")
    ]
    cls = resolve_confirmation_class(" ".join(p for p in parts if p))

    # Out of the arbiter's domain: a heuristic finding with neither stored
    # artifacts nor a confirmation class (e.g. a fuzzer crash, a binary-analysis
    # hit). Leave its locally-justified tier untouched.
    if not present and cls is None:
        return FindingAdjudication(
            tier=model_tier,
            applicable=False,
            model_tier=model_tier,
            verdict=None,
            reasons=(),
        )

    neg_required = cls is not None and cls.value in _NEGATIVE_CONTROL_CLASS_VALUES
    neg_present = _negative_control_value(root) is not None if root else False
    class_confirmed = (
        evaluate_class_confirmation(cls, poc_outer).confirmed if cls is not None else None
    )

    verdict = adjudicate(
        artifacts=(),
        vuln_class=cls.value if cls is not None else None,
        present_kinds=present or None,
        negative_control_required=neg_required,
        negative_control_present=neg_present,
        repeatability=None,
        interference=False,
        class_confirmed=class_confirmed,
    )

    arbiter_tier = int(verdict.tier)
    # Cap-only: the arbiter lowers an unprovable tier, never raises one.
    final_tier = min(model_tier, arbiter_tier) if model_tier is not None else arbiter_tier

    return FindingAdjudication(
        tier=final_tier,
        applicable=True,
        model_tier=model_tier,
        verdict=verdict,
        reasons=tuple(str(r) for r in verdict.reasons),
    )


__all__ = ["FindingAdjudication", "adjudicate_finding_tier"]
