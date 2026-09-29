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
    PROMPT_PLACEHOLDER = "prompt_placeholder"
    PROMPT_INSTRUCTION = "prompt_instruction"
    CHAT_ARTIFACT = "chat_artifact"
    RAW_JSON = "raw_json"
    QUESTIONNAIRE_ECHO = "questionnaire_echo"


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

# --------------------------------------------------------------------------- #
# Phase T (§29) — prompt-artifact and response-form validation.
# The model answered, but its output was published unchecked. These patterns
# block prompt placeholders, echoed prompt instructions, chat artifacts,
# questionnaire echoes and raw JSON leaking into a prose slot (R-03…R-09).
# --------------------------------------------------------------------------- #

#: (StopGroup, compiled regex). Regex-based, unlike the substring STOP_LIST.
_ARTIFACT_PATTERNS: tuple[tuple[StopGroup, re.Pattern[str]], ...] = (
    # Unfilled prompt placeholders (§29.1).
    (StopGroup.PROMPT_PLACEHOLDER, re.compile(r"\[Layer\]", re.IGNORECASE)),
    (StopGroup.PROMPT_PLACEHOLDER, re.compile(r"\[Config/file\]", re.IGNORECASE)),
    (StopGroup.PROMPT_PLACEHOLDER, re.compile(r"\[specific value\]", re.IGNORECASE)),
    (StopGroup.PROMPT_PLACEHOLDER, re.compile(r"\[curl command\]", re.IGNORECASE)),
    (StopGroup.PROMPT_PLACEHOLDER, re.compile(r"\[Quick Fix\]", re.IGNORECASE)),
    (StopGroup.PROMPT_PLACEHOLDER, re.compile(r"\[Moderate\]", re.IGNORECASE)),
    (StopGroup.PROMPT_PLACEHOLDER, re.compile(r"\[Complex Refactor\]", re.IGNORECASE)),
    (StopGroup.PROMPT_PLACEHOLDER, re.compile(r"\[specific [^\]]*?\]", re.IGNORECASE)),
    (StopGroup.PROMPT_PLACEHOLDER, re.compile(r"\[insert [^\]]*?\]", re.IGNORECASE)),
    (StopGroup.PROMPT_PLACEHOLDER, re.compile(r"\[TBD\]", re.IGNORECASE)),
    (StopGroup.PROMPT_PLACEHOLDER, re.compile(r"\{\{.*?\}\}")),
    # Prompt instructions returned as content (§29.1).
    (StopGroup.PROMPT_INSTRUCTION, re.compile(r"Tag each fix", re.IGNORECASE)),
    (
        StopGroup.PROMPT_INSTRUCTION,
        re.compile(r"Verification command \(curl or tool command\) for each fix", re.IGNORECASE),
    ),
    (
        StopGroup.PROMPT_INSTRUCTION,
        re.compile(r"Concrete configuration examples only for detected stack evidence", re.I),
    ),
    (
        StopGroup.PROMPT_INSTRUCTION,
        re.compile(r"Stack-neutral control if the stack is unknown", re.IGNORECASE),
    ),
    (StopGroup.PROMPT_INSTRUCTION, re.compile(r"^\s*Verification method:\s*$", re.MULTILINE)),
    # Chat artifacts (§29.1).
    (StopGroup.CHAT_ARTIFACT, re.compile(r"I hope this", re.IGNORECASE)),
    (StopGroup.CHAT_ARTIFACT, re.compile(r"Let me know if", re.IGNORECASE)),
    (StopGroup.CHAT_ARTIFACT, re.compile(r"As an AI", re.IGNORECASE)),
    (StopGroup.CHAT_ARTIFACT, re.compile(r"\bI cannot\b", re.IGNORECASE)),
    (StopGroup.CHAT_ARTIFACT, re.compile(r"^\s*Certainly!", re.IGNORECASE | re.MULTILINE)),
    (StopGroup.CHAT_ARTIFACT, re.compile(r"^\s*Here is\b", re.IGNORECASE | re.MULTILINE)),
    # Echo of the prompt's numbered questionnaire instead of prose (§29.1).
    (
        StopGroup.QUESTIONNAIRE_ECHO,
        re.compile(r"^\s*\d\.\s+(No|Yes|There (is|are) no)\b", re.MULTILINE),
    ),
    # Unescaped unicode escape sequences leaking from a JSON dump (§29.1).
    (StopGroup.RAW_JSON, re.compile(r"\\u[0-9a-f]{4}", re.IGNORECASE)),
)

#: Verification-command flags that DISABLE the property being verified (R-06, §29.3).
_INSECURE_FLAG_RE = re.compile(
    r"(--insecure|(?<!\w)-k(?!\w)|--no-check-certificate|verify\s*=\s*False)",
    re.IGNORECASE,
)

#: Chain-claim phrases — only admissible when a proven chain exists (R-07, §29.3).
#: Deliberately narrow to *assertive* wording ("can be chained", "chained with X to …")
#: so section titles ("Exploit Chain") and honest negatives ("no attack chain was
#: demonstrated") do NOT trip the gate — only an actual claim of a chain does.
_CHAIN_CLAIM_RE = re.compile(
    r"(can be chained"
    r"|chained (?:with|together|to)"
    r"|chain(?:ed|ing)?\s+\w+(?:\s+\w+){0,6}\s+to\s+(?:create|achieve|escalate|gain|obtain)"
    r"|по\s+цепочке"
    r"|объединить\s+в\s+цепочк)",
    re.IGNORECASE,
)

#: A full-length UUID (finding_id) and a truncated UUID-looking token (R-08).
_UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_UUID_PREFIX_RE = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{1,11}\b", re.I
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


def find_prompt_artifacts(text: str) -> list[tuple[StopGroup, str]]:
    """Return (group, matched-fragment) for every prompt-artifact hit (§29.1)."""
    hits: list[tuple[StopGroup, str]] = []
    for group, pattern in _ARTIFACT_PATTERNS:
        m = pattern.search(text or "")
        if m:
            hits.append((group, m.group(0).strip()[:80]))
    return hits


def is_raw_json_prose(text: str) -> bool:
    """True when a prose slot's first non-empty char is ``{`` (a JSON dump, R-05)."""
    stripped = (text or "").strip()
    if not stripped:
        return False
    # Tolerate a leading ```json fence, then require the body to be a JSON object.
    if stripped.startswith("```"):
        stripped = stripped.split("\n", 1)[-1].strip() if "\n" in stripped else stripped
    return stripped.startswith("{") and (":" in stripped)


def insecure_verification_flags(text: str) -> list[str]:
    """Return verification-command flags that disable the checked property (R-06)."""
    return [m.group(0) for m in _INSECURE_FLAG_RE.finditer(text or "")]


def truncated_finding_ids(text: str, known_finding_ids: set[str]) -> list[str]:
    """Return UUID-looking tokens that are a *prefix* of a known id but not full (R-08)."""
    full = set(_UUID_RE.findall(text or ""))
    offenders: list[str] = []
    for token in _UUID_PREFIX_RE.findall(text or ""):
        if token in full or token in known_finding_ids:
            continue
        if any(fid.startswith(token) for fid in known_finding_ids):
            offenders.append(token)
    return offenders


def _parse_counts(text: str) -> tuple[int, dict[str, int]] | None:
    """Parse ``N finding(s) recorded`` + ``critical: X, high: Y…`` (R-10)."""
    total_m = re.search(r"(\d+)\s+finding\(?s?\)?\s+recorded", text or "", re.IGNORECASE)
    if not total_m:
        return None
    bands: dict[str, int] = {}
    for band in ("critical", "high", "medium", "low", "informational", "info"):
        bm = re.search(rf"{band}\s*:\s*(\d+)", text or "", re.IGNORECASE)
        if bm:
            bands[band] = int(bm.group(1))
    if not bands:
        return None
    return int(total_m.group(1)), bands


def check_output_consistency(
    text: str,
    *,
    known_finding_ids: set[str] | None = None,
    has_proven_chains: bool = False,
    wstg_coverage_pct: float | None = None,
    section: str = "",
) -> list[ProseViolation]:
    """Cross-check a model's text against report facts (§29.3, R-06…R-12).

    * chain claims require a proven chain (R-07);
    * finding ids must be full-length (R-08);
    * a verification command must not disable the checked property (R-06);
    * severity counters must sum to the stated total (R-10);
    * a stated WSTG coverage must equal the canonical value (R-12).
    """
    known_finding_ids = known_finding_ids or set()
    out: list[ProseViolation] = []
    loc = section or "section"

    if _CHAIN_CLAIM_RE.search(text or "") and not has_proven_chains:
        out.append(
            ProseViolation(
                "chain_claim_without_proven_chain",
                ProseSeverity.BLOCK,
                f"chain claim in '{loc}' but no proven exploit chain exists (R-07)",
            )
        )

    for token in truncated_finding_ids(text, known_finding_ids):
        out.append(
            ProseViolation(
                "truncated_finding_id",
                ProseSeverity.BLOCK,
                f"truncated finding id '{token}' in '{loc}' (R-08)",
            )
        )

    for flag in insecure_verification_flags(text):
        out.append(
            ProseViolation(
                "insecure_verification_command",
                ProseSeverity.BLOCK,
                f"verification command in '{loc}' disables the checked property: '{flag}' (R-06)",
            )
        )

    parsed = _parse_counts(text)
    if parsed is not None:
        total, bands = parsed
        if sum(bands.values()) != total:
            out.append(
                ProseViolation(
                    "counter_mismatch",
                    ProseSeverity.BLOCK,
                    f"severity counters sum to {sum(bands.values())} but total is {total} (R-10)",
                )
            )

    if wstg_coverage_pct is not None:
        for m in re.finditer(r"WSTG[^%\d]{0,40}?(\d+(?:\.\d+)?)\s*%", text or "", re.IGNORECASE):
            stated = float(m.group(1))
            if abs(stated - float(wstg_coverage_pct)) > 0.5:
                out.append(
                    ProseViolation(
                        "wstg_coverage_mismatch",
                        ProseSeverity.BLOCK,
                        f"stated WSTG coverage {stated}% ≠ canonical {wstg_coverage_pct}% (R-12)",
                    )
                )

    return out


def evaluate_prose(
    text: str,
    *,
    section: str = "",
    require_references: bool = True,
    slot_type: str = "prose",
) -> list[ProseViolation]:
    """Evaluate a rendered section body against the prose gate (§19, §29).

    ``require_references`` should be False for methodology / disclaimer sections where
    reference-free prose is legitimate. ``slot_type`` is ``prose`` | ``structured_json``
    | ``table``; a ``prose`` slot that is a raw JSON document is rejected (R-05).
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

    for group, fragment in find_prompt_artifacts(text):
        violations.append(
            ProseViolation(
                rule=f"prompt_artifact:{group.value}",
                severity=ProseSeverity.BLOCK,
                detail=f"prompt artifact in '{section or 'section'}': '{fragment}'",
            )
        )

    if slot_type == "prose" and is_raw_json_prose(text):
        violations.append(
            ProseViolation(
                rule="raw_json_in_prose_slot",
                severity=ProseSeverity.BLOCK,
                detail=f"prose slot '{section or 'section'}' contains a raw JSON document (R-05)",
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
    "check_output_consistency",
    "evaluate_prose",
    "find_prompt_artifacts",
    "find_stop_phrases",
    "has_reference",
    "insecure_verification_flags",
    "is_raw_json_prose",
    "truncated_finding_ids",
]
