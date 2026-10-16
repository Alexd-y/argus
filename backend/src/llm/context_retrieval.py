"""Retrieve-not-stuff grounding context (Wave 5, R-9.12).

Instead of trying to fit the whole knowledge base into a prompt (expensive and a
hallucination magnet), retrieve the few relevant fragments from the project's own
RAG store (``src/rag/``) and inject a SIZE-CAPPED, citeable block. Pairs with
source grounding (R-9.10): each fragment gets a ``[KB-n]`` label the model is told
to cite, and a claim that cites nothing resolvable is dropped.

``build_grounding_context`` is a pure formatter over a retrieval pack (duck-typed:
``.citations[].snippet`` preferred, else ``.chunks[].content``), fully testable
offline; ``retrieve_grounding_context`` is a thin best-effort wrapper over a
:class:`src.rag.retrieval.RagRetriever`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_MAX_CHARS = 4000
_DEFAULT_MAX_RESULTS = 5


@dataclass(frozen=True)
class GroundingContext:
    text: str  # the labeled, capped block to inject into the prompt
    labels: tuple[str, ...]  # citeable [KB-n] labels, in order
    fragment_count: int
    truncated: bool


def _fragments(pack: Any) -> list[str]:
    cits = getattr(pack, "citations", None) or []
    if cits:
        return [str(getattr(c, "snippet", "") or "") for c in cits]
    return [str(getattr(ch, "content", "") or "") for ch in (getattr(pack, "chunks", None) or [])]


def build_grounding_context(pack: Any, *, max_chars: int = _DEFAULT_MAX_CHARS) -> GroundingContext:
    """Format a retrieval pack into a size-capped, [KB-n]-labeled context block."""
    lines: list[str] = []
    labels: list[str] = []
    used = 0
    truncated = False
    for raw in _fragments(pack):
        snippet = raw.strip()
        if not snippet:
            continue
        label = f"KB-{len(labels) + 1}"  # sequential over KEPT fragments (no gaps)
        entry = f"[{label}] {snippet}"
        if lines and used + len(entry) + 1 > max_chars:
            truncated = True
            break
        lines.append(entry)
        labels.append(label)
        used += len(entry) + 1
    return GroundingContext(
        text="\n".join(lines),
        labels=tuple(labels),
        fragment_count=len(lines),
        truncated=truncated,
    )


async def retrieve_grounding_context(
    retriever: Any,
    *,
    text: str,
    tenant_id: str,
    engagement_id: str | None,
    mode: str,
    max_chars: int = _DEFAULT_MAX_CHARS,
    max_results: int = _DEFAULT_MAX_RESULTS,
) -> GroundingContext:
    """Retrieve relevant fragments and format them. Best-effort → empty on failure.

    ``RagRetriever.retrieve`` is synchronous; this wrapper is async so callers in
    the async scan path can await it uniformly.
    """
    try:
        from src.rag.schemas import RagQuery

        query = RagQuery(text=text, max_results=max_results)
        pack = retriever.retrieve(query, tenant_id, engagement_id, mode)
        return build_grounding_context(pack, max_chars=max_chars)
    except Exception:  # pragma: no cover - defensive; retrieval never breaks the call
        logger.debug("retrieve_grounding_context: suppressed best-effort error", exc_info=True)
        return GroundingContext(text="", labels=(), fragment_count=0, truncated=False)


__all__ = ["GroundingContext", "build_grounding_context", "retrieve_grounding_context"]
