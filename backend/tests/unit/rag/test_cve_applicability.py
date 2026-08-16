"""CVE applicability requires product and version evidence."""

from __future__ import annotations

from src.rag.cve_applicability import assess_cve_applicability, extract_cve_ids
from src.rag.schemas import CollectionName, RagChunk

_CHUNK_ID = "11111111-1111-1111-1111-111111111111"


def _chunk(content: str, **metadata: str) -> RagChunk:
    return RagChunk(
        id=_CHUNK_ID,
        document_id=_CHUNK_ID,
        source_id=_CHUNK_ID,
        collection=CollectionName.PUBLIC_INTEL,
        chunk_index=0,
        content=content,
        content_hash="a" * 64,
        metadata=metadata,
    )


def test_extracts_normalized_cve_ids() -> None:
    assert extract_cve_ids("see cve-2024-1234 and CVE-2024-1234") == ("CVE-2024-1234",)


def test_product_and_version_make_cve_applicable() -> None:
    chunk = _chunk(
        "nginx 1.25 is affected by CVE-2024-1234",
        product="nginx",
        product_version="1.25.0",
    )
    rows = assess_cve_applicability("Target is vulnerable to CVE-2024-1234", [chunk])
    assert len(rows) == 1
    assert rows[0].status == "applicable"
    assert rows[0].product == "nginx"
    assert rows[0].version == "1.25.0"


def test_cve_without_product_version_is_inferred() -> None:
    chunk = _chunk("Advisory mentions CVE-2024-1234 in passing")
    rows = assess_cve_applicability("CVE-2024-1234 looks relevant", [chunk])
    assert rows[0].status == "inferred"


def test_cve_without_matching_chunk_is_uncited() -> None:
    chunk = _chunk("unrelated TLS cipher discussion")
    rows = assess_cve_applicability("CVE-2024-9999 is applicable", [chunk])
    assert rows[0].status == "uncited"
