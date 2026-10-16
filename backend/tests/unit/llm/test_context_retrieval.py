"""Wave 5 / R-9.12 — retrieve-not-stuff grounding context."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

from src.llm.context_retrieval import (
    build_grounding_context,
    retrieve_grounding_context,
)


@dataclass
class _Cit:
    snippet: str


@dataclass
class _Chunk:
    content: str


class _Pack:
    def __init__(self, citations=None, chunks=None):
        self.citations = citations or []
        self.chunks = chunks or []


def test_builds_labeled_block_from_citations():
    pack = _Pack(citations=[_Cit("SQLi needs a single quote"), _Cit("XSS reflects input")])
    ctx = build_grounding_context(pack)
    assert ctx.fragment_count == 2
    assert ctx.labels == ("KB-1", "KB-2")
    assert "[KB-1] SQLi needs a single quote" in ctx.text
    assert "[KB-2] XSS reflects input" in ctx.text
    assert ctx.truncated is False


def test_falls_back_to_chunks_when_no_citations():
    pack = _Pack(chunks=[_Chunk("chunk body one")])
    ctx = build_grounding_context(pack)
    assert ctx.fragment_count == 1
    assert "[KB-1] chunk body one" in ctx.text


def test_empty_fragments_skipped():
    pack = _Pack(citations=[_Cit("  "), _Cit("real")])
    ctx = build_grounding_context(pack)
    assert ctx.fragment_count == 1
    assert ctx.labels == ("KB-1",)  # blank skipped; numbering continues from kept


def test_cap_truncates_and_flags():
    big = "x" * 500
    pack = _Pack(citations=[_Cit(big), _Cit(big), _Cit(big)])
    ctx = build_grounding_context(pack, max_chars=600)
    assert ctx.truncated is True
    assert ctx.fragment_count == 1  # only the first fits under 600 chars


def test_empty_pack_yields_empty_context():
    ctx = build_grounding_context(_Pack())
    assert ctx.text == "" and ctx.labels == () and ctx.fragment_count == 0


def test_retrieve_wrapper_is_best_effort():
    class _BadRetriever:
        def retrieve(self, *a, **k):
            raise RuntimeError("store down")

    ctx = asyncio.run(
        retrieve_grounding_context(
            _BadRetriever(), text="q", tenant_id="t", engagement_id=None, mode="production"
        )
    )
    assert ctx.text == "" and ctx.fragment_count == 0


def test_retrieve_wrapper_formats_pack():
    class _OkRetriever:
        def retrieve(self, query, tenant_id, engagement_id, mode):
            assert query.text == "find sqli"
            return _Pack(citations=[_Cit("evidence of sqli")])

    ctx = asyncio.run(
        retrieve_grounding_context(
            _OkRetriever(), text="find sqli", tenant_id="t", engagement_id="e", mode="production"
        )
    )
    assert ctx.fragment_count == 1
    assert "[KB-1] evidence of sqli" in ctx.text
