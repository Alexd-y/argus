"""Proof-strength honesty semantics ported from ARTEX ``report/quality.go`` (WP B).

ARGUS reports are already richer than ARTEX; what this module ports is the *honesty
semantics* of doability, rendered through the existing Valhalla theme (no colour,
font or logo change). Three ideas carry over:

1. **Proof-strength per finding** — a PoE (proof-of-exploitation) level, the
   verification status with a human note, a confidence *rationale*, the
   **counterevidence** ("what we tried that did not work"), and the count of
   *bound* evidence (artifacts that actually resolve in the snapshot).

2. **Three-state honesty** — the key ARTEX contribution. A proof-strength row is
   one of :class:`ProofState`:

   * ``PRESENT``     — a quality row exists and was read;
   * ``MISSING``     — no quality row was recorded (an honest gap, printed);
   * ``UNAVAILABLE`` — the lookup itself failed (DB/store error).

   A lookup error is **never** rendered as "not vulnerable" or "unverified": an
   availability error is a data problem, not a verdict about the finding.

3. **Stale-report detection** — a single predicate, shared by the report and every
   exporter, that flags when a report was written against an older evidence
   version so the surfaces never disagree.

Pure module: no DB, LLM or network. It reads already-shaped finding records
(``ReportFinding`` or plain dicts) and returns value objects for the renderers.
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

__all__ = [
    "ProofState",
    "ProofStrength",
    "build_finding_proof_strength",
    "compute_proof_strength",
    "evidence_version_is_stale",
    "stale_banner",
]


class ProofState(StrEnum):
    """Three-state honesty for a finding's proof-strength row (ARTEX)."""

    PRESENT = "present"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"


#: PoE (proof-of-exploitation) ladder derived from the verification status.
_POE_BY_STATUS: dict[str, str] = {
    "exploitable": "proven-exploitable",
    "confirmed": "proven",
    "suspected": "partial",
    "observed": "partial",
    "inconclusive": "unverified",
    "insufficient_evidence": "unverified",
    "not_tested": "unverified",
    "not_assessed": "unverified",
    "out_of_scope": "unverified",
    "false_positive": "refuted",
}

#: Verification statuses that assert a quality row exists even with no evidence/PoC
#: attached yet (an assessment was made). ``not_assessed`` / ``not_tested`` /
#: ``out_of_scope`` are deliberately absent — a never-assessed finding has no row.
_ASSESSED_STATUSES: frozenset[str] = frozenset(
    {
        "confirmed",
        "exploitable",
        "suspected",
        "observed",
        "inconclusive",
        "insufficient_evidence",
        "false_positive",
    }
)

#: Statuses whose PoE is below "proven" — surfaced in the rationale so the honest
#: gap is explicit rather than implied.
_PARTIAL_STATUSES: frozenset[str] = frozenset(
    {"suspected", "observed", "inconclusive", "insufficient_evidence", "not_tested"}
)

_UNAVAILABLE_LABEL = "proof strength unavailable"
_MISSING_LABEL = "proof strength not recorded"


@dataclass(frozen=True)
class ProofStrength:
    """The proof-strength row for one finding (value object for renderers)."""

    state: ProofState
    poe_level: str
    verification_status: str
    verification_note: str
    confidence_rationale: str
    counterevidence: list[str] = field(default_factory=list)
    bound_evidence_count: int = 0
    label: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Flat mapping for templates / JSON / exporters (parity across formats)."""
        return {
            "state": self.state.value,
            "poe_level": self.poe_level,
            "verification_status": self.verification_status,
            "verification_note": self.verification_note,
            "confidence_rationale": self.confidence_rationale,
            "counterevidence": list(self.counterevidence),
            "bound_evidence_count": self.bound_evidence_count,
            "label": self.label,
        }


def _get(obj: Any, name: str) -> Any:
    if isinstance(obj, dict):
        return obj.get(name)
    return getattr(obj, name, None)


def _collect_counterevidence(finding: Any) -> list[str]:
    """Gather "what we tried that did not work" for this observation.

    Sources: the explicit ``counterevidence`` list, plus the ``downgrade_reason``
    (why a stronger claim was withheld). The PoC's ``negative_control`` is *not*
    counterevidence — a passing control *proves* the finding — so it is excluded.
    """
    out: list[str] = []
    for item in _get(finding, "counterevidence") or []:
        text = str(item).strip()
        if text and text not in out:
            out.append(text)
    downgrade = _get(finding, "downgrade_reason")
    if downgrade:
        text = str(downgrade).strip()
        if text and text not in out:
            out.append(text)
    return out


def _count_bound_evidence(
    finding: Any, known_evidence_ids: set[str] | frozenset[str] | None
) -> int:
    """Count evidence artifacts that actually *resolve* in the snapshot.

    Referential when ``known_evidence_ids`` is provided (an id that does not
    resolve does not count — matching the snapshot evidence gate); cardinal
    fallback otherwise. A ``raw_artifact_ref`` counts as one bound artifact.
    """
    evidence_ids = list(_get(finding, "evidence_ids") or [])
    if known_evidence_ids is None:
        bound = len(evidence_ids)
    else:
        bound = sum(1 for e in evidence_ids if e in known_evidence_ids)
    if _get(finding, "raw_artifact_ref"):
        bound += 1
    return bound


def _confidence_rationale(finding: Any, *, status: str, bound: int) -> str:
    parts: list[str] = []
    confidence = _get(finding, "confidence")
    if confidence is not None:
        with contextlib.suppress(TypeError, ValueError):
            parts.append(f"model confidence {float(confidence):.2f}")
    # Honest gap — a zero bound-evidence claim says so explicitly (never hidden).
    if bound == 0:
        parts.append("zero bound evidence")
    else:
        parts.append(f"{bound} bound evidence artifact(s)")
    if status in _PARTIAL_STATUSES:
        parts.append(f"status '{status}' — not proven-exploitable")
    return "; ".join(parts) if parts else f"status '{status}'"


def _verification_note(finding: Any, *, status: str) -> str:
    downgrade = _get(finding, "downgrade_reason")
    if status == "observed" and downgrade:
        return f"downgraded to observed: {downgrade}"
    if status == "false_positive":
        return "assessed as false positive"
    if status in ("confirmed", "exploitable"):
        return "verified against a bound evidence chain"
    return f"status: {status}"


def compute_proof_strength(
    finding: Any,
    *,
    known_evidence_ids: set[str] | frozenset[str] | None = None,
    lookup_error: BaseException | None = None,
) -> ProofStrength:
    """Compute the proof-strength row for one finding (three-state honest).

    ``finding`` is a ``ReportFinding`` or a plain dict. ``known_evidence_ids`` is
    the set of evidence ids / object keys that resolve in the snapshot (for the
    referential bound-evidence count). ``lookup_error`` is passed by the caller
    when the proof-strength *lookup itself* failed — which yields ``UNAVAILABLE``,
    never a "not vulnerable" / "unverified" verdict.
    """
    # UNAVAILABLE — a data-availability error, not a determination about the
    # finding. Worded to avoid both "not vulnerable" and the unverified verdict.
    if lookup_error is not None:
        return ProofStrength(
            state=ProofState.UNAVAILABLE,
            poe_level="unavailable",
            verification_status="unavailable",
            verification_note=(
                f"proof-strength lookup failed ({type(lookup_error).__name__}); "
                "this is a data-availability error, not a verdict on the finding"
            ),
            confidence_rationale="proof strength unavailable — evidence lookup error",
            counterevidence=[],
            bound_evidence_count=0,
            label=_UNAVAILABLE_LABEL,
        )

    status = str(_get(finding, "verification_status") or "not_assessed").strip().lower()
    evidence_ids = list(_get(finding, "evidence_ids") or [])
    poc = _get(finding, "poc")
    raw_ref = _get(finding, "raw_artifact_ref")
    counter = _collect_counterevidence(finding)
    bound = _count_bound_evidence(finding, known_evidence_ids)

    has_quality_row = (
        status in _ASSESSED_STATUSES
        or bool(evidence_ids)
        or poc is not None
        or bool(counter)
        or bool(raw_ref)
    )
    if not has_quality_row:
        # MISSING — an honest gap, printed rather than silently omitted.
        return ProofStrength(
            state=ProofState.MISSING,
            poe_level="unverified",
            verification_status=status,
            verification_note="no proof-strength row was recorded for this observation",
            confidence_rationale="proof strength not recorded",
            counterevidence=[],
            bound_evidence_count=bound,
            label=_MISSING_LABEL,
        )

    poe = _POE_BY_STATUS.get(status, "unverified")
    return ProofStrength(
        state=ProofState.PRESENT,
        poe_level=poe,
        verification_status=status,
        verification_note=_verification_note(finding, status=status),
        confidence_rationale=_confidence_rationale(finding, status=status, bound=bound),
        counterevidence=counter,
        bound_evidence_count=bound,
        label=f"proof strength: {poe}",
    )


#: Legacy template-row vocabulary (``evidence_classification`` /
#: ``validation_status``) → canonical ``verification_status``. The report row dicts
#: built in ``generators.py`` predate the canonical ``ReportFinding`` status field;
#: this is the single place that bridges the two so proof-strength is identical
#: regardless of which finding shape a surface carries.
_EVIDENCE_CLASS_TO_STATUS: dict[str, str] = {
    "validated": "confirmed",
    "confirmed": "confirmed",
    "exploited": "exploitable",
    "exploitable": "exploitable",
    "observed": "observed",
    "candidate": "suspected",
    "suspected": "suspected",
    "inconclusive": "inconclusive",
    "unverified": "insufficient_evidence",
    "insufficient_evidence": "insufficient_evidence",
    "false_positive": "false_positive",
}


def _normalize_status(finding: Any) -> str:
    """Resolve a canonical verification status from either finding shape."""
    canonical = _get(finding, "verification_status")
    if canonical:
        return str(canonical).strip().lower()
    if _get(finding, "exploit_demonstrated"):
        return "exploitable"
    for key in ("evidence_classification", "validation_status", "status"):
        raw = _get(finding, key)
        if raw:
            mapped = _EVIDENCE_CLASS_TO_STATUS.get(str(raw).strip().lower())
            if mapped:
                return mapped
    return "not_assessed"


def build_finding_proof_strength(
    finding: Any,
    *,
    known_evidence_ids: set[str] | frozenset[str] | None = None,
    lookup_error: BaseException | None = None,
) -> ProofStrength:
    """Proof-strength for a finding of *either* shape — canonical ``ReportFinding`` or
    the legacy template row (``evidence_classification`` / ``evidence_refs`` /
    ``unconfirmed_reason``).

    The vocabulary difference is resolved here once, then deferred to
    :func:`compute_proof_strength`. Any mapping/lookup error degrades to
    ``UNAVAILABLE`` — an honest availability state, never a blank or "not vulnerable".
    """
    if lookup_error is not None:
        return compute_proof_strength(finding, lookup_error=lookup_error)
    try:
        counter: list[str] = [str(c) for c in (_get(finding, "counterevidence") or [])]
        for alt in ("downgrade_reason", "unconfirmed_reason"):
            value = _get(finding, alt)
            if value:
                counter.append(str(value))
        evidence_ids = _get(finding, "evidence_ids") or _get(finding, "evidence_refs") or []
        normalized = {
            "verification_status": _normalize_status(finding),
            "evidence_ids": list(evidence_ids),
            "counterevidence": counter,
            "raw_artifact_ref": _get(finding, "raw_artifact_ref"),
            "poc": _get(finding, "poc") or _get(finding, "proof_of_concept"),
            "confidence": _get(finding, "confidence"),
        }
        return compute_proof_strength(normalized, known_evidence_ids=known_evidence_ids)
    except Exception as exc:  # noqa: BLE001 - any shaping error → honest UNAVAILABLE
        return compute_proof_strength(finding, lookup_error=exc)


def evidence_version_is_stale(built_against: Any, current: Any) -> bool:
    """Single stale-evidence predicate shared by the report and every exporter.

    ``True`` only when both versions are known *and* differ. An unknown current
    version is not an alarm — honest, not alarmist.
    """
    if built_against is None or current is None:
        return False
    return str(built_against).strip() != str(current).strip()


def stale_banner(built_against: Any, current: Any) -> dict[str, Any] | None:
    """Structured stale banner for rendering, or ``None`` when not stale."""
    if not evidence_version_is_stale(built_against, current):
        return None
    return {
        "built_against": built_against,
        "current": current,
        "message": (
            f"This report was written against an older evidence snapshot "
            f"({built_against}); the current evidence version is {current}."
        ),
    }
