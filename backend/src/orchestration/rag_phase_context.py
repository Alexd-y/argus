"""Phase RAG collaborator — tenant-scoped evidence packs for planner/TM/VA.

Handlers and ``ai_prompts`` call this module; they must not know FTS/pgvector.
Retrieval goes through ``RagRetriever``; citation gating uses ``apply_citation_gate``.
Fail-open: RAG errors or missing scope → empty pack with ``needs_evidence``.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import Any, Final

from src.capabilities.graph import default_capability_graph
from src.execution_mode.mode import ExecutionMode, parse_execution_mode
from src.llm.prompts.prompts_pack import RAG_QUERY_PLANNER_V2
from src.llm.schemas import LlmResponseStatus
from src.rag.citations import apply_citation_gate
from src.rag.cve_applicability import assess_cve_applicability
from src.rag.retrieval import RagRetriever
from src.rag.schemas import (
    ALL_COLLECTIONS,
    LAB_ONLY_COLLECTIONS,
    CollectionName,
    RagChunk,
    RagCitation,
    RagEvidencePack,
    RagQuery,
)

logger = logging.getLogger(__name__)

RAG_QUERY_PLANNER_PROMPT_ID: Final[str] = "rag_query_planner_v2"
_QUERY_MAX: Final[int] = 4000
_SNIPPET_MAX: Final[int] = 512
_LAB_ARTIFACT_CLASSES: Final[frozenset[str]] = frozenset(
    {"lab_artifact", "raw_payload", "raw_template", "raw_lab"}
)
_PLANNER_ALIASES: Final[frozenset[str]] = frozenset(
    {
        "planner",
        "scan_planner",
        "recon",
        "source_analysis",
        "orchestration",
    }
)
_PLANNER_COLLECTIONS: Final[tuple[CollectionName, ...]] = (
    CollectionName.TOOL_CATALOG,
    CollectionName.CAPABILITY_GRAPH,
    CollectionName.API_SURFACE,
    CollectionName.CODEBASE,
    CollectionName.SECURITY_STANDARDS,
    CollectionName.DETECTION_TEMPLATES,
)
_TM_COLLECTIONS: Final[tuple[CollectionName, ...]] = (
    CollectionName.PUBLIC_INTEL,
    CollectionName.SECURITY_STANDARDS,
    CollectionName.FINDING_HISTORY,
    CollectionName.SCAN_EVIDENCE,
    CollectionName.CAPABILITY_GRAPH,
    CollectionName.CODEBASE,
)
_VA_COLLECTIONS: Final[tuple[CollectionName, ...]] = (
    CollectionName.SCAN_EVIDENCE,
    CollectionName.FINDING_HISTORY,
    CollectionName.DETECTION_TEMPLATES,
    CollectionName.PAYLOAD_CATALOG,
    CollectionName.CODEBASE,
    CollectionName.API_SURFACE,
    CollectionName.PUBLIC_INTEL,
)
_DEFAULT_COLLECTIONS: Final[tuple[CollectionName, ...]] = (
    CollectionName.SCAN_EVIDENCE,
    CollectionName.FINDING_HISTORY,
    CollectionName.PUBLIC_INTEL,
)
_QUICK_COLLECTIONS: Final[tuple[CollectionName, ...]] = (
    CollectionName.TOOL_CATALOG,
    CollectionName.CAPABILITY_GRAPH,
    CollectionName.DETECTION_TEMPLATES,
    CollectionName.SECURITY_STANDARDS,
    CollectionName.PUBLIC_INTEL,
    CollectionName.FINDING_HISTORY,
)
_PHASE_COLLECTIONS: Final[dict[str, tuple[CollectionName, ...]]] = {
    "planner": _PLANNER_COLLECTIONS,
    "threat_modeling": _TM_COLLECTIONS,
    "vuln_analysis": _VA_COLLECTIONS,
    "quick_planner": _QUICK_COLLECTIONS,
    "quick_fingerprint": _QUICK_COLLECTIONS,
    "quick_triage": _QUICK_COLLECTIONS,
    "quick_critic": _QUICK_COLLECTIONS,
    "quick_reporter": _QUICK_COLLECTIONS,
}

_retriever: RagRetriever | None = None


def get_phase_rag_retriever() -> RagRetriever:
    """Return the process retriever (InMemory store unless tests inject another)."""
    global _retriever
    if _retriever is None:
        _retriever = RagRetriever()
    return _retriever


def configure_phase_rag_retriever(retriever: RagRetriever | None) -> None:
    """Inject or clear the process retriever (tests / DI)."""
    global _retriever
    _retriever = retriever


def normalize_rag_phase(phase: str) -> str:
    """Map recon/scan-planner aliases onto the planner collection set."""
    key = (phase or "").strip().lower()
    if key in _PLANNER_ALIASES:
        return "planner"
    return key


def collections_for_phase(
    phase: str,
    mode: ExecutionMode | str,
    asset_types: Sequence[str] = (),
) -> tuple[CollectionName, ...]:
    """Graph-driven collection plan merged with the phase catalog.

    Always includes ``argus_product``, ``episodic_validated``, and
    ``capability_graph``. LAB may include ``lab_research``; production and
    quick never request it.
    """
    resolved = parse_execution_mode(mode)
    phase_key = normalize_rag_phase(phase)
    catalog = _PHASE_COLLECTIONS.get(phase_key, _DEFAULT_COLLECTIONS)
    graph_names = default_capability_graph().collections_for_phase(
        phase_key,
        resolved.value,
        asset_types,
    )
    merged: list[CollectionName] = []
    seen: set[CollectionName] = set()
    for raw in (*catalog, *graph_names):
        try:
            name = raw if isinstance(raw, CollectionName) else CollectionName(str(raw))
        except ValueError:
            continue
        if name not in ALL_COLLECTIONS or name in seen:
            continue
        seen.add(name)
        merged.append(name)
    if resolved is ExecutionMode.LAB_UNRESTRICTED:
        if CollectionName.LAB_RESEARCH not in seen:
            merged.append(CollectionName.LAB_RESEARCH)
        return tuple(merged)
    return tuple(item for item in merged if item not in LAB_ONLY_COLLECTIONS)


def format_rag_pack_for_prompt(pack: RagEvidencePack) -> str:
    """Render citation IDs + snippets for a phase prompt. Never invents CVE."""
    status = str(pack.metadata.get("status") or LlmResponseStatus.OK.value)
    lines = [
        "=== RAG EVIDENCE PACK ===",
        f"status: {status}",
        f"prompt_id: {RAG_QUERY_PLANNER_PROMPT_ID}",
    ]
    if not pack.citations:
        lines.extend(
            [
                "No retrieved evidence.",
                "Do not invent CVE, CWE, CVSS, or execution results.",
                "=== END RAG EVIDENCE PACK ===",
            ]
        )
        return "\n".join(lines)

    lines.append("Cite facts with [cite:<chunk_hash>] and citation id. Do not invent CVE identifiers.")
    for citation in pack.citations:
        snippet = citation.snippet[:_SNIPPET_MAX]
        lines.append(
            f"[cite:{citation.chunk_hash}] id={citation.id} "
            f"collection={citation.collection.value} rank={citation.rank}"
        )
        lines.append(snippet)
    if pack.inferred_claims:
        lines.append("inferred_claims:")
        lines.extend(f"- {claim}" for claim in pack.inferred_claims)
    lines.append("=== END RAG EVIDENCE PACK ===")
    return "\n".join(lines)


def render_phase_rag_section(
    phase: str,
    tenant_id: str,
    engagement_id: str,
    mode: ExecutionMode | str,
    query: str,
    *,
    retriever: RagRetriever | None = None,
) -> str:
    """Build a pack and format it for planner/TM/VA prompts (fail-open)."""
    pack = build_phase_rag_pack(
        phase,
        tenant_id,
        engagement_id,
        mode,
        query,
        retriever=retriever,
    )
    return format_rag_pack_for_prompt(pack)


def build_phase_rag_pack(
    phase: str,
    tenant_id: str,
    engagement_id: str,
    mode: ExecutionMode | str,
    query: str,
    *,
    retriever: RagRetriever | None = None,
    collections: Sequence[CollectionName] | None = None,
) -> RagEvidencePack:
    """Retrieve a tenant+engagement scoped evidence pack for one phase.

    Fail-open: missing scope or RAG errors return an empty pack with
    ``needs_evidence``. Does not invent CVE identifiers.
    """
    resolved_mode = parse_execution_mode(mode)
    scoped_tenant = (tenant_id or "").strip()
    scoped_engagement = (engagement_id or "").strip()
    query_text = _bounded_query(query, phase)
    planned = collections_for_phase(phase, resolved_mode)
    requested = tuple(collections) if collections is not None else planned
    requested = _filter_collections_for_mode(requested, resolved_mode)

    if not scoped_tenant or not scoped_engagement:
        return _empty_pack(
            phase=phase,
            tenant_id=scoped_tenant or "unscoped",
            engagement_id=scoped_engagement or None,
            mode=resolved_mode,
            query_text=query_text,
            collections=requested,
            reason="missing_tenant_or_engagement",
        )

    pack = _retrieve_or_empty(
        phase=phase,
        tenant_id=scoped_tenant,
        engagement_id=scoped_engagement,
        mode=resolved_mode,
        query_text=query_text,
        collections=requested,
        retriever=retriever,
    )
    pack = _strip_lab_artifacts_for_production(pack, resolved_mode)
    pack = _apply_pack_citation_gate(pack)
    pack = _with_cve_applicability(pack)
    return _with_planner_metadata(pack, phase, requested, LlmResponseStatus.OK.value)


def _retrieve_or_empty(
    *,
    phase: str,
    tenant_id: str,
    engagement_id: str,
    mode: ExecutionMode,
    query_text: str,
    collections: Sequence[CollectionName],
    retriever: RagRetriever | None,
) -> RagEvidencePack:
    active = retriever if retriever is not None else get_phase_rag_retriever()
    try:
        return active.retrieve(
            RagQuery(text=query_text, collections=tuple(collections), max_results=10),
            tenant_id,
            engagement_id,
            mode,
            collections,
            profile="quick" if mode is ExecutionMode.QUICK else None,
        )
    except Exception:
        logger.warning(
            "rag_phase_retrieve_failed",
            extra={
                "event": "rag_phase_retrieve_failed",
                "phase": normalize_rag_phase(phase),
                "mode": mode.value,
            },
        )
        return _empty_pack(
            phase=phase,
            tenant_id=tenant_id,
            engagement_id=engagement_id,
            mode=mode,
            query_text=query_text,
            collections=collections,
            reason="rag_unavailable",
        )


def _bounded_query(query: str, phase: str) -> str:
    text = " ".join((query or "").split())
    if not text:
        text = f"{normalize_rag_phase(phase)} evidence"
    return text[:_QUERY_MAX]


def _filter_collections_for_mode(
    collections: Sequence[CollectionName],
    mode: ExecutionMode,
) -> tuple[CollectionName, ...]:
    if mode is ExecutionMode.LAB_UNRESTRICTED:
        return tuple(collections)
    return tuple(item for item in collections if item not in LAB_ONLY_COLLECTIONS)


def _is_lab_artifact(chunk: RagChunk) -> bool:
    if chunk.collection in LAB_ONLY_COLLECTIONS:
        return True
    return chunk.content_class in _LAB_ARTIFACT_CLASSES


def _strip_lab_artifacts_for_production(
    pack: RagEvidencePack,
    mode: ExecutionMode,
) -> RagEvidencePack:
    if mode is ExecutionMode.LAB_UNRESTRICTED:
        return pack
    kept_chunks = tuple(chunk for chunk in pack.chunks if not _is_lab_artifact(chunk))
    if len(kept_chunks) == len(pack.chunks):
        return pack
    kept_ids = {chunk.id for chunk in kept_chunks}
    kept_citations = tuple(item for item in pack.citations if item.chunk_id in kept_ids)
    status = (
        LlmResponseStatus.OK.value
        if kept_chunks
        else LlmResponseStatus.NEEDS_EVIDENCE.value
    )
    metadata = dict(pack.metadata)
    metadata["status"] = status
    metadata["lab_artifacts_stripped"] = True
    return pack.model_copy(
        update={
            "chunks": kept_chunks,
            "citations": kept_citations,
            "metadata": metadata,
        }
    )


def _cited_body(citations: Sequence[RagCitation]) -> str:
    parts: list[str] = []
    for citation in citations:
        snippet = citation.snippet[:_SNIPPET_MAX]
        parts.append(f"[cite:{citation.chunk_hash}] {snippet}")
    return " ".join(parts)


def _apply_pack_citation_gate(pack: RagEvidencePack) -> RagEvidencePack:
    if not pack.citations:
        return pack
    gated = apply_citation_gate(_cited_body(pack.citations), pack.citations)
    if not gated.inferred_claims:
        return pack
    return pack.model_copy(update={"inferred_claims": tuple(gated.inferred_claims)})


def _with_cve_applicability(pack: RagEvidencePack) -> RagEvidencePack:
    blob = " ".join(chunk.content for chunk in pack.chunks)
    rows = assess_cve_applicability(blob, pack.chunks)
    if not rows:
        return pack
    metadata = dict(pack.metadata)
    metadata["cve_applicability"] = [
        {
            "cve_id": item.cve_id,
            "status": item.status,
            "product": item.product or "",
            "version": item.version or "",
            "chunk_id": item.chunk_id or "",
        }
        for item in rows
    ]
    return pack.model_copy(update={"metadata": metadata})


def _planner_metadata(
    phase: str,
    collections: Sequence[CollectionName],
    status: str,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "status": status,
        "phase": normalize_rag_phase(phase),
        "query_planner_prompt_id": RAG_QUERY_PLANNER_PROMPT_ID,
        "query_planner_prompt": RAG_QUERY_PLANNER_V2,
        "collections": [item.value for item in collections],
    }
    if extra:
        payload.update(extra)
    return payload


def _with_planner_metadata(
    pack: RagEvidencePack,
    phase: str,
    collections: Sequence[CollectionName],
    status: str,
) -> RagEvidencePack:
    metadata = dict(pack.metadata)
    hit_status = status if pack.chunks else LlmResponseStatus.NEEDS_EVIDENCE.value
    metadata.update(_planner_metadata(phase, collections, hit_status))
    return pack.model_copy(update={"metadata": metadata})


def _empty_pack(
    *,
    phase: str,
    tenant_id: str,
    engagement_id: str | None,
    mode: ExecutionMode,
    query_text: str,
    collections: Sequence[CollectionName],
    reason: str,
) -> RagEvidencePack:
    return RagEvidencePack(
        query=RagQuery(text=query_text, collections=tuple(collections), max_results=10),
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        mode=mode.value,
        citations=(),
        chunks=(),
        inferred_claims=(),
        metadata=_planner_metadata(
            phase,
            collections,
            LlmResponseStatus.NEEDS_EVIDENCE.value,
            extra={"fail_open_reason": reason},
        ),
    )


__all__ = [
    "RAG_QUERY_PLANNER_PROMPT_ID",
    "build_phase_rag_pack",
    "collections_for_phase",
    "configure_phase_rag_retriever",
    "format_rag_pack_for_prompt",
    "get_phase_rag_retriever",
    "normalize_rag_phase",
    "render_phase_rag_section",
]
