"""CVE applicability — product/version evidence required (master prompt §7.4)."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

from src.rag.schemas import RagChunk

CveStatus = Literal["applicable", "inferred", "uncited"]

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d+\b", re.IGNORECASE)


@dataclass(frozen=True)
class CveApplicability:
    cve_id: str
    status: CveStatus
    product: str | None = None
    version: str | None = None
    chunk_id: str | None = None


def extract_cve_ids(text: str) -> tuple[str, ...]:
    found = [_normalize_cve(match.group(0)) for match in _CVE_RE.finditer(text or "")]
    return tuple(dict.fromkeys(found))


def _normalize_cve(value: str) -> str:
    return value.strip().upper()


def _chunk_product(chunk: RagChunk) -> str:
    raw = chunk.metadata.get("product") or chunk.metadata.get("product_name") or ""
    return str(raw).strip().lower()


def _chunk_version(chunk: RagChunk) -> str:
    raw = chunk.metadata.get("product_version") or chunk.metadata.get("version") or ""
    return str(raw).strip().lower()


def _chunk_mentions_cve(chunk: RagChunk, cve_id: str) -> bool:
    needle = cve_id.lower()
    if needle in chunk.content.lower():
        return True
    return needle in str(chunk.metadata).lower()


def assess_cve_applicability(
    text: str,
    chunks: Sequence[RagChunk],
) -> tuple[CveApplicability, ...]:
    """Semantic CVE mention alone is never ``applicable``."""
    results: list[CveApplicability] = []
    for cve_id in extract_cve_ids(text):
        applicable: CveApplicability | None = None
        inferred: CveApplicability | None = None
        for chunk in chunks:
            if not _chunk_mentions_cve(chunk, cve_id):
                continue
            product = _chunk_product(chunk)
            version = _chunk_version(chunk)
            if product and version:
                applicable = CveApplicability(
                    cve_id=cve_id,
                    status="applicable",
                    product=product,
                    version=version,
                    chunk_id=chunk.id,
                )
                break
            if inferred is None:
                inferred = CveApplicability(
                    cve_id=cve_id,
                    status="inferred",
                    chunk_id=chunk.id,
                )
        if applicable is not None:
            results.append(applicable)
        elif inferred is not None:
            results.append(inferred)
        else:
            results.append(CveApplicability(cve_id=cve_id, status="uncited"))
    return tuple(results)
