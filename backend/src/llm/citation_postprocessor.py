"""Gateway citation post-processor — uncited facts become inference."""

from __future__ import annotations

from collections.abc import Sequence

from src.llm.schemas import Citation
from src.rag.citations import apply_citation_gate
from src.rag.cve_applicability import assess_cve_applicability
from src.rag.schemas import CollectionName, RagChunk, RagCitation


def citations_from_evidence_refs(evidence_refs: Sequence[str]) -> list[RagCitation]:
    citations: list[RagCitation] = []
    for index, raw in enumerate(evidence_refs, start=1):
        digest = (raw or "").strip()
        if len(digest) < 8:
            continue
        citations.append(
            RagCitation(
                id=digest[:36],
                chunk_id=digest[:36],
                chunk_hash=digest[:128],
                document_id=digest[:36],
                source_id=digest[:36],
                collection=CollectionName.SCAN_EVIDENCE,
                rank=index,
                score=1.0,
                snippet="",
            )
        )
    return citations


def envelope_citations(rag_citations: Sequence[RagCitation]) -> list[Citation]:
    return [
        Citation(
            chunk_id=item.chunk_id,
            source_id=item.source_id,
            sha256=item.chunk_hash,
        )
        for item in rag_citations
    ]


def postprocess_response_text(
    text: str,
    *,
    evidence_refs: Sequence[str],
    chunks: Sequence[RagChunk] = (),
) -> tuple[str, list[str], list[Citation], list[dict[str, str]]]:
    """Gate uncited claims and classify CVE applicability."""
    rag_citations = citations_from_evidence_refs(evidence_refs)
    gated = apply_citation_gate(text, rag_citations)
    cve_rows = [
        {
            "cve_id": item.cve_id,
            "status": item.status,
            "product": item.product or "",
            "version": item.version or "",
        }
        for item in assess_cve_applicability(text, chunks)
    ]
    return (
        gated.text,
        list(gated.inferred_claims),
        envelope_citations(rag_citations),
        cve_rows,
    )
