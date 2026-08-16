"""Citation gate — uncited factual claims become inference."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from src.eval.rates import record_citation_claim
from src.rag.schemas import RagCitation

_FACTUAL_CLAIM_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\bCVE-\d{4}-\d+\b",
        r"\bCWE-\d+\b",
        r"\bCVSS\s*[:=]?\s*\d+(?:\.\d+)?",
        r"\b(sql injection|xss|ssrf|rce|lfi|idor)\b",
        r"\b(exploit|vulnerability|remediation|patch)\b",
        r"\b(request|response|artifact|stdout|stderr)\b",
        r"\b(applicable|affects|confirmed|verified)\b",
    )
)

_CITATION_REF_PATTERN = re.compile(
    r"\[(?:cite|ref|citation)[:\s]*([a-f0-9]{8,128})\]",
    re.IGNORECASE,
)


@dataclass
class GatedText:
    """Text after citation gate processing."""

    text: str
    inferred_claims: list[str] = field(default_factory=list)
    cited_hashes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def extract_citation_hashes(text: str) -> list[str]:
    """Extract explicit citation hash references from text."""
    return list(_CITATION_REF_PATTERN.findall(text))


def _is_factual_claim(sentence: str) -> bool:
    stripped = sentence.strip()
    if len(stripped) < 8:
        return False
    return any(pattern.search(stripped) for pattern in _FACTUAL_CLAIM_PATTERNS)


def _split_sentences(text: str) -> list[str]:
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return [part.strip() for part in parts if part.strip()]


def apply_citation_gate(
    text: str,
    citations: Sequence[RagCitation],
    *,
    mark_inference: bool = True,
) -> GatedText:
    """Mark uncited factual claims as inference or strip them."""
    cited_hashes = {citation.chunk_hash for citation in citations}
    explicit_refs = set(extract_citation_hashes(text))
    all_cited = cited_hashes | explicit_refs

    sentences = _split_sentences(text)
    kept: list[str] = []
    inferred: list[str] = []

    for sentence in sentences:
        sentence_refs = set(extract_citation_hashes(sentence))
        has_citation = bool(sentence_refs & all_cited)
        factual = _is_factual_claim(sentence)

        if factual and not has_citation:
            record_citation_claim(cited=False)
            inferred.append(sentence)
            if mark_inference:
                kept.append(f"[INFERENCE] {sentence}")
            continue
        if factual:
            record_citation_claim(cited=True)
        kept.append(sentence)

    return GatedText(
        text=" ".join(kept).strip(),
        inferred_claims=inferred,
        cited_hashes=list(all_cited),
        metadata={"citation_count": len(citations)},
    )


class CitationGate:
    """Deterministic post-processor for cited evidence packs."""

    def gate(
        self,
        text: str,
        citations: Sequence[RagCitation],
        *,
        mark_inference: bool = True,
    ) -> GatedText:
        return apply_citation_gate(text, citations, mark_inference=mark_inference)

    def resolve_citation_hash(
        self,
        chunk_hash: str,
        citations: Sequence[RagCitation],
    ) -> RagCitation | None:
        for citation in citations:
            if citation.chunk_hash == chunk_hash:
                return citation
        return None
