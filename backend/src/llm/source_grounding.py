"""Source grounding for claim-generating tasks (Wave 5, R-9.10).

Wave 4 enforced resolvable ``[CL-…]`` / ``[E-…]`` references in the final report
prose. R-9.10 pushes the same principle UPSTREAM to the tasks that GENERATE
claims: the model must cite the identifiers of actually-collected evidence, and
a claim whose reference does not resolve is discarded.

This module is the generating-task layer. It reuses the canonical reference
primitives from :mod:`src.reports.prose_gate` (one reference grammar across the
system) and adds:

* :func:`grounding_instruction` — the system-prompt clause that obliges the model
  to cite only from the supplied evidence labels;
* :func:`filter_grounded_claims` — drop any claim that carries no reference or an
  unresolvable one, keeping the grounded ones.

Pure and offline-testable.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from src.reports.prose_gate import has_reference, unresolvable_references


def grounding_instruction(labels: Iterable[str], *, max_listed: int = 40) -> str:
    """Build the system-prompt clause that forces evidence-grounded claims."""
    uniq = sorted({str(label).strip() for label in labels if str(label).strip()})
    shown = ", ".join(uniq[:max_listed])
    more = "" if len(uniq) <= max_listed else f" (+{len(uniq) - max_listed} more)"
    return (
        "GROUNDING REQUIREMENT: every claim you make MUST cite at least one "
        "evidence reference in [E-...] or [CL-...] form, drawn ONLY from these "
        f"collected evidence labels: [{shown}]{more}. A claim without a "
        "resolvable reference will be discarded. Never invent labels."
    )


@dataclass(frozen=True)
class GroundingResult:
    kept: tuple[str, ...]
    dropped: tuple[tuple[str, str], ...]  # (claim, reason)

    @property
    def kept_rate(self) -> float:
        total = len(self.kept) + len(self.dropped)
        return len(self.kept) / total if total else 0.0


def filter_grounded_claims(
    claims: Iterable[str],
    known_labels: Iterable[str],
) -> GroundingResult:
    """Keep only claims with at least one RESOLVABLE evidence reference.

    A claim is dropped with reason ``"no_reference"`` when it cites nothing, or
    ``"unresolvable:<labels>"`` when it cites labels that resolve to no collected
    evidence (a dangling pointer). Reuses the report prose-gate grammar so the
    generating tasks and the final report judge references identically.
    """
    known = frozenset(str(label) for label in known_labels)
    kept: list[str] = []
    dropped: list[tuple[str, str]] = []
    for claim in claims:
        text = str(claim)
        if not has_reference(text):
            dropped.append((text, "no_reference"))
            continue
        unresolved = unresolvable_references(text, known)
        if unresolved:
            dropped.append((text, "unresolvable:" + ",".join(unresolved)))
            continue
        kept.append(text)
    return GroundingResult(kept=tuple(kept), dropped=tuple(dropped))


__all__ = ["GroundingResult", "filter_grounded_claims", "grounding_instruction"]
