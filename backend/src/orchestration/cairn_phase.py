"""Cairn ↔ ARGUS pipeline integration seam (Phase 9).

Two integration modes (flag-gated, off by default):

* **Mode A** — Cairn as the inner loop of a phase (vuln_analysis / exploitation /
  post_exploitation): ``scan_options.cairn_enabled`` + ``scan_options.cairn_phases``.
* **Mode B** — Cairn as an alternative scan engine: ``scan_options.engine == "cairn"``.

The load-bearing, safety-critical piece is the **Fact → Finding** bridge (§11.3): a
Cairn fact is free text, so it only becomes a Finding through the evidence gate.
Rule #4 is enforced here — a fact with no artifact and no evidence refs can never be
promoted above :class:`EvidenceTier.SUSPECTED`. Provenance links every promoted
finding back to its Cairn project / fact / intent for report traceability.

Mirrors the flag-gated design of ``adaptive_phase.py``: this module is pure and
importable without a DB; the state machine calls these helpers.
"""

from __future__ import annotations

from typing import Any

from src.orchestration.evidence_tier import EvidenceTier
from src.orchestration.finding_gate import (
    EvidenceQuality,
    evidence_quality_of,
    gate_and_dedupe_findings,
)

_DEFAULT_CAIRN_PHASES: frozenset[str] = frozenset(
    {"vuln_analysis", "exploitation", "post_exploitation"}
)


def cairn_engine_mode(scan_options: dict[str, Any] | None) -> str:
    """Return the scan engine: ``"cairn"`` or ``"pipeline"`` (default)."""
    opts = scan_options or {}
    engine = str(opts.get("engine", "pipeline")).strip().lower()
    return "cairn" if engine == "cairn" else "pipeline"


def cairn_inner_loop_enabled(scan_options: dict[str, Any] | None, phase: str) -> bool:
    """Whether Cairn should run as the inner loop of ``phase`` (Mode A)."""
    opts = scan_options or {}
    if not bool(opts.get("cairn_enabled", False)):
        return False
    phases = opts.get("cairn_phases")
    allowed = (
        frozenset(phases)
        if isinstance(phases, list | tuple | set) and phases
        else _DEFAULT_CAIRN_PHASES
    )
    return phase in allowed


def _fact_has_evidence(fact: dict[str, Any]) -> bool:
    return bool(fact.get("artifact_object_key")) or bool(fact.get("evidence_refs"))


def cap_evidence_tier(fact: dict[str, Any]) -> EvidenceTier:
    """Cap a fact's evidence tier by the evidence it actually carries (§11.3 #4).

    A fact with no artifact and no evidence refs cannot exceed ``SUSPECTED``,
    regardless of any tier the model requested.
    """
    requested_raw = fact.get("evidence_tier")
    try:
        requested = (
            EvidenceTier(int(requested_raw))
            if requested_raw is not None
            else EvidenceTier.SUSPECTED
        )
    except (ValueError, TypeError):
        requested = EvidenceTier.SUSPECTED
    if not _fact_has_evidence(fact):
        return min(requested, EvidenceTier.SUSPECTED, key=int)
    return requested


def fact_to_finding(
    fact: dict[str, Any],
    *,
    project_id: str,
    intent_ref: str | None = None,
) -> dict[str, Any]:
    """Map a Cairn fact dict to a Finding candidate dict with provenance + tier cap."""
    description = str(fact.get("description", "")).strip()
    title = description.splitlines()[0][:200] if description else "Cairn finding"
    tier = cap_evidence_tier(fact)
    return {
        "title": title,
        "description": description,
        "source": "cairn",
        "source_tool": "cairn",
        "evidence_refs": list(fact.get("evidence_refs") or []),
        "artifact_object_key": fact.get("artifact_object_key"),
        "evidence_tier": int(tier),
        "confidence": fact.get("confidence"),
        "provenance": {
            "cairn_project_id": project_id,
            "cairn_fact_ref": fact.get("ref"),
            "cairn_intent_ref": intent_ref,
        },
    }


def promote_facts_to_findings(
    facts: list[dict[str, Any]],
    *,
    project_id: str,
    intent_ref_by_fact: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """Convert interesting facts into gated, de-duplicated Finding candidates.

    Facts whose evidence quality is ``NONE`` (placeholder / no signal) are dropped;
    survivors are capped at ``SUSPECTED`` when they carry no artifact/evidence, then
    passed through the shared finding gate + dedup.
    """
    ref_map = intent_ref_by_fact or {}
    candidates: list[dict[str, Any]] = []
    for fact in facts:
        ref = str(fact.get("ref", ""))
        if ref in ("origin", "goal"):
            continue  # special facts are context, not findings
        candidate = fact_to_finding(fact, project_id=project_id, intent_ref=ref_map.get(ref))
        if evidence_quality_of(candidate) is EvidenceQuality.NONE and not candidate["description"]:
            continue
        candidates.append(candidate)
    return gate_and_dedupe_findings(candidates)


__all__ = [
    "cairn_engine_mode",
    "cairn_inner_loop_enabled",
    "cap_evidence_tier",
    "fact_to_finding",
    "promote_facts_to_findings",
]
