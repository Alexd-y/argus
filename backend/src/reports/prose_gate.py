"""Prose gate (Part II, Phase N) — text discipline for Valhalla report sections.

Normative base: §19 of ``CURSOR_VALHALLA_REPORT_FIX_PROMPT.md``. LLM output drifts to
bureaucratic filler and unfounded escalations; this gate blocks it.

Two layers:

* a **stop-list** (blocking) of unfounded escalations, empty recommendations, stubs,
  false certainty in negation and bureaucratic filler — grouped so callers can require
  one representative phrase per group in tests;
* **structural rules**: a factual paragraph in a technical section must carry at least
  one ``[CL-…]`` / ``[E-…]`` reference; no absolute safety claims; recommendations must
  reference a concrete component.

Pure module (no DB / LLM / network). Callers run generated section text through
:func:`evaluate_prose` before accepting it; violations feed the release gate.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class StopGroup(StrEnum):
    UNFOUNDED_ESCALATION = "unfounded_escalation"
    EMPTY_RECOMMENDATION = "empty_recommendation"
    STUB = "stub"
    FALSE_NEGATION_CERTAINTY = "false_negation_certainty"
    BUREAUCRATESE = "bureaucratese"


#: Grouped stop-list (§19.1). Matching is case-insensitive substring on normalized text.
STOP_LIST: dict[StopGroup, tuple[str, ...]] = {
    StopGroup.UNFOUNDED_ESCALATION: (
        "полная компрометация",
        "complete compromise",
        "full system takeover",
        "позволяет злоумышленнику получить полный контроль",
    ),
    StopGroup.EMPTY_RECOMMENDATION: (
        "применяйте best practices",
        "follow security best practices",
        "обеспечьте валидацию ввода",
        "input validation and output encoding",
        "рекомендуется обновить до последней версии",
    ),
    StopGroup.STUB: (
        "poc details are available in asgard",
        "poc details are available in valhalla",
        "not implemented",
        "todo",
        "анализ будет выполнен",
        "pending",
    ),
    StopGroup.FALSE_NEGATION_CERTAINTY: (
        "уязвимостей не обнаружено",
        "система защищена",
        "соответствует требованиям",
        "no vulnerabilities were found",
    ),
    StopGroup.BUREAUCRATESE: (
        "в рамках проведённого исследования было выявлено, что",
        "необходимо отметить, что",
    ),
}

#: Flat view of every stop phrase (for quick membership checks / iteration).
ALL_STOP_PHRASES: tuple[str, ...] = tuple(p for group in STOP_LIST.values() for p in group)

#: A factual reference marker: ``[CL-0042]``, ``[E-101]`` or ``[CL-0042 / E-101]``.
_REFERENCE_RE = re.compile(r"\[\s*(?:CL|E)-[0-9A-Za-z._/\- ]+\]", re.IGNORECASE)

#: Absolute safety assertions are never allowed regardless of context (§19.2).
_ABSOLUTE_SAFETY_RE = re.compile(
    r"(система\s+(?:полностью\s+)?защищена"
    r"|полностью\s+безопас"
    r"|no\s+security\s+(?:issues|vulnerabilities)\s+(?:exist|remain)"
    r"|fully\s+secure)",
    re.IGNORECASE,
)


class ProseSeverity(StrEnum):
    BLOCK = "block"
    NEEDS_REVIEW = "needs_review"


@dataclass
class ProseViolation:
    rule: str
    severity: ProseSeverity
    detail: str


def find_stop_phrases(text: str) -> list[tuple[StopGroup, str]]:
    """Return every (group, phrase) stop-list hit in ``text`` (case-insensitive)."""
    lowered = (text or "").lower()
    hits: list[tuple[StopGroup, str]] = []
    for group, phrases in STOP_LIST.items():
        for phrase in phrases:
            if phrase in lowered:
                hits.append((group, phrase))
    return hits


def has_reference(paragraph: str) -> bool:
    """Whether a paragraph carries at least one ``[CL-…]`` / ``[E-…]`` reference."""
    return bool(_REFERENCE_RE.search(paragraph or ""))


def _split_paragraphs(text: str) -> list[str]:
    return [p.strip() for p in re.split(r"\n\s*\n", text or "") if p.strip()]


# A paragraph is "factual" (needs a reference) unless it is clearly methodological /
# a heading / a list scaffold. Heuristic: prose with a sentence-ending period and no
# reference, that is not a markdown heading or bullet-only line.
_METHODOLOGICAL_HINTS = (
    "методолог",
    "methodolog",
    "область работ",
    "scope",
    "ограничени",
    "limitation",
    "оговорк",
    "disclaimer",
)


def _is_methodological(paragraph: str) -> bool:
    low = paragraph.lower()
    return any(h in low for h in _METHODOLOGICAL_HINTS)


def evaluate_prose(
    text: str,
    *,
    section: str = "",
    require_references: bool = True,
) -> list[ProseViolation]:
    """Evaluate a rendered section body against the prose gate (§19).

    ``require_references`` should be False for methodology / disclaimer sections where
    reference-free prose is legitimate.
    """
    violations: list[ProseViolation] = []

    for group, phrase in find_stop_phrases(text):
        violations.append(
            ProseViolation(
                rule=f"stop_list:{group.value}",
                severity=ProseSeverity.BLOCK,
                detail=f"stop-list phrase present in '{section or 'section'}': '{phrase}'",
            )
        )

    if _ABSOLUTE_SAFETY_RE.search(text or ""):
        violations.append(
            ProseViolation(
                rule="absolute_safety_claim",
                severity=ProseSeverity.BLOCK,
                detail=f"absolute safety/compliance claim in '{section or 'section'}'",
            )
        )

    if require_references:
        for para in _split_paragraphs(text):
            # Skip markdown headings, bullet-only scaffolding and methodological prose.
            if para.startswith("#") or para.startswith(("- ", "* ", "|")):
                continue
            if _is_methodological(para):
                continue
            # Only flag paragraphs that read like a factual statement (contain a period
            # and are reasonably long) but carry no reference.
            if len(para) >= 40 and "." in para and not has_reference(para):
                violations.append(
                    ProseViolation(
                        rule="paragraph_without_reference",
                        severity=ProseSeverity.NEEDS_REVIEW,
                        detail=(
                            f"factual paragraph without [CL-…]/[E-…] reference in "
                            f"'{section or 'section'}': {para[:80]}…"
                        ),
                    )
                )

    return violations


def blocking_violations(violations: list[ProseViolation]) -> list[ProseViolation]:
    return [v for v in violations if v.severity == ProseSeverity.BLOCK]


__all__ = [
    "ALL_STOP_PHRASES",
    "STOP_LIST",
    "ProseSeverity",
    "ProseViolation",
    "StopGroup",
    "blocking_violations",
    "evaluate_prose",
    "find_stop_phrases",
    "has_reference",
]
