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
  has visibility into it — it carries a *verified* stored artifact OR resolves
  to an *active-exploitation* confirmation class (XSS/SQLi/SSRF/RCE/CMDi/IDOR/
  BOLA/auth-bypass), whose evidence model IS the raw exchange. Heuristic findings
  (fuzzer crashes, binary-analysis hits) and passive classes whose proof is not a
  raw exchange (TLS/headers, CVE-by-version, rate-limiting) are returned
  **unchanged** so their locally-justified tier survives.
* **Verified artifacts only.** A raw-exchange kind (HAR/PCAP) and an impact-proof
  kind (screenshot/video) count ONLY when ``verify_artifact(key)`` confirms the
  object genuinely exists in the evidence store — a content-addressed *shape* is
  necessary but NOT sufficient (the format is public and the PoC is model-authored,
  so a shape-only check would let a model forge ``har_evidence_key`` and fabricate
  a CONFIRMED/EXPLOITED tier). With no verifier the gate is fail-closed: no
  PoC-declared artifact is credited.

``repeatability`` and ``interference`` are not collected per-finding at this
site yet, so they are passed as "not checked"; the arbiter records that
honestly and does not cap on them here.

The confirmation-class helpers come from the lightweight
:mod:`src.pipeline.contracts.confirmation_rules` (not the heavy ``reports``
package), so adjudication cannot be disabled by a report-stack import failure.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from src.pipeline.contracts.confirmation_rules import (
    _negative_control_value,
    _poc_root,
    evaluate_class_confirmation,
    resolve_confirmation_class,
)
from src.pipeline.contracts.evidence_arbiter import ArbiterVerdict, adjudicate
from src.pipeline.contracts.finding_dto import EvidenceKind

#: Confirmation-class *values* in the arbiter's domain — active-exploitation
#: classes whose canonical evidence IS a request/response exchange (so an
#: artifactless CONFIRMED claim is genuinely unproven and should be demoted).
#: Passive classes (rate_limiting, cve_version, tls_headers) are deliberately
#: excluded: their proof is a handshake / header set / version banner, which the
#: arbiter's HAR/PCAP model does not represent, so the arbiter must not judge
#: them (it would wrongly demote legitimate passive findings).
_ACTIVE_CLASS_VALUES: frozenset[str] = frozenset(
    {"xss", "sqli", "ssrf", "rce", "cmdi", "idor", "bola", "auth_bypass"}
)

#: Confirmation-class *values* whose rule mandates a negative control
#: (poc_validation ``_rule_idor`` / ``_rule_auth_bypass``). A subset of the
#: active classes. A missing negative control caps the tier at SUSPECTED (R-5.4).
_NEGATIVE_CONTROL_CLASS_VALUES: frozenset[str] = frozenset({"idor", "bola", "auth_bypass"})

#: A genuine content-addressed evidence object key ends in ``{kind}-{hex}.bin``
#: (``EvidencePipeline._prepare`` → ``f"{kind.value}-{sha256[:16]}.bin"``). We
#: match the basename so any storage prefix is tolerated. This is a cheap
#: pre-filter only — existence is still verified via ``verify_artifact``.
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


def _present_kinds(
    poc_outer: dict[str, Any],
    root: dict[str, Any],
    verify_artifact: Callable[[str], bool] | None,
) -> frozenset[EvidenceKind]:
    """Evidence kinds for which this finding genuinely stored an artifact.

    Every kind is credited ONLY when ``verify_artifact(key)`` confirms the object
    exists in the store (fail-closed when no verifier is supplied). HAR/PCAP are
    additionally shape-checked against the content-addressed pattern as a cheap
    pre-filter before the (I/O) existence check.
    """
    if verify_artifact is None:
        return frozenset()

    kinds: set[EvidenceKind] = set()

    def _str(key: str) -> str:
        # Only the CANONICAL key each ARGUS producer actually writes is read —
        # loose aliases (``har``/``har_key`` …) could only ever come from
        # untrusted model output, so they are deliberately not accepted.
        for container in (poc_outer, root):
            val = container.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
        return ""

    har = _str("har_evidence_key")
    if har and _CONTENT_ADDRESSED.search(har) and verify_artifact(har):
        kinds.add(EvidenceKind.HAR)
    pcap = _str("pcap_evidence_key")
    if pcap and _CONTENT_ADDRESSED.search(pcap) and verify_artifact(pcap):
        kinds.add(EvidenceKind.PCAP)
    screenshot = _str("screenshot_key")
    if screenshot and verify_artifact(screenshot):
        kinds.add(EvidenceKind.SCREENSHOT)
    video = _str("video_key")
    if video and verify_artifact(video):
        kinds.add(EvidenceKind.VIDEO)
    return frozenset(kinds)


def adjudicate_finding_tier(
    finding: dict[str, Any],
    *,
    verify_artifact: Callable[[str], bool] | None = None,
) -> FindingAdjudication:
    """Adjudicate one finding dict's :class:`EvidenceTier` from its collected
    artifacts and the wave-3 gates.

    ``verify_artifact(object_key) -> bool`` is the integrity gate: it must return
    True only when a genuinely-stored object exists for that key. Production
    callers pass a store-backed checker; omitting it is fail-closed (no
    PoC-declared artifact is credited).

    Returns a :class:`FindingAdjudication`. When the finding is outside the
    arbiter's visibility (no verified artifact and no active-exploitation class)
    the result is ``applicable=False`` and ``tier`` is the unchanged model tier.
    """
    model_tier = _coerce_tier(finding.get("evidence_tier"))

    poc_outer = finding.get("proof_of_concept")
    poc_outer = poc_outer if isinstance(poc_outer, dict) else {}
    root = _poc_root(poc_outer) if poc_outer else {}

    present = _present_kinds(poc_outer, root, verify_artifact)
    parts = [
        str(finding.get(key) or "")
        for key in ("title", "name", "cwe", "owasp_category", "vuln_type", "category")
    ]
    cls = resolve_confirmation_class(" ".join(p for p in parts if p))
    is_active = cls is not None and cls.value in _ACTIVE_CLASS_VALUES

    # Out of the arbiter's domain: neither a verified stored artifact nor an
    # active-exploitation class. Leave the locally-justified tier untouched
    # (fuzzer crash, binary-analysis hit, passive TLS/header/version finding).
    if not present and not is_active:
        return FindingAdjudication(
            tier=model_tier,
            applicable=False,
            model_tier=model_tier,
            verdict=None,
            reasons=(),
        )

    neg_required = is_active and cls.value in _NEGATIVE_CONTROL_CLASS_VALUES
    neg_present = _negative_control_value(root) is not None if root else False
    # The per-class bar is only meaningful for an active class (its rule models a
    # raw-exchange proof). For an artifact-only, non-active finding leave it
    # unchecked rather than applying an ill-fitting passive rule.
    class_confirmed = evaluate_class_confirmation(cls, poc_outer).confirmed if is_active else None

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
