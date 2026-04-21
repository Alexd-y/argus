"""Parser for ``hash-analyzer --json`` output (Backlog §4.13 — ARG-029).

``hash-analyzer`` produces a richer classification than ``hashid``: it
adds entropy estimates and HMAC / chain detection.  Two upstream
shapes are supported:

* ``[{"input": "...", "matches": [...], "entropy": 4.0}, ...]``
* ``{"results": [{"input": "...", "matches": [...]}, ...]}``

Where ``matches`` is a list of ``{"name": "...", "confidence": 0.92,
"hashcat": 1000, "john": "raw-md5"}`` (confidence is occasionally
absent on legacy builds).

Translation rules
-----------------

* Each input becomes one INFO finding tagged
  :class:`FindingCategory.CRYPTO` with CWE-326 / 327.  As with hashid,
  the cleartext hash is NEVER stored — only ``stable_hash_12``,
  length, entropy and the matched algorithms are persisted.
* The match with the highest ``confidence`` (or, on ties, the lower
  hashcat mode id) becomes ``preferred_mode``.
* Confidence on the FindingDTO is :class:`ConfidenceLevel.LIKELY`
  unless the top match's score is ``>= 0.95`` — then we promote to
  :class:`ConfidenceLevel.CONFIRMED`.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "hash_analyzer_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "hash_analyzer.json"
_MAX_FINDINGS: Final[int] = 5_000
_HIGH_CONFIDENCE_THRESHOLD: Final[float] = 0.95


DedupKey: TypeAlias = tuple[str, str]


def parse_hash_analyzer_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate hash-analyzer output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if payload is None:
        return []
    entries = _normalise_payload(payload, tool_id=tool_id)
    if not entries:
        return []
    records = list(_iter_records(entries, tool_id=tool_id))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


def _normalise_payload(payload: Any, *, tool_id: str) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        results = payload.get("results")
        if isinstance(results, list):
            return [item for item in results if isinstance(item, dict)]
        if "input" in payload:
            return [payload]
    _logger.warning(
        "hash_analyzer_parser.unsupported_payload",
        extra={
            "event": "hash_analyzer_parser_unsupported_payload",
            "tool_id": tool_id,
            "actual_type": type(payload).__name__,
        },
    )
    return []


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            str(record.get("hash_id") or ""),
            str(record.get("preferred_mode") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            str(record.get("hash_id") or ""),
            str(record.get("preferred_mode") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "hash_analyzer_parser.cap_reached",
                extra={
                    "event": "hash_analyzer_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break
    keyed.sort(key=lambda item: item[0])
    if keyed:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR_NAME,
            evidence_records=[blob for _, _, blob in keyed],
            tool_id=tool_id,
        )
    return [finding for _, finding, _ in keyed]


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    confidence = ConfidenceLevel.LIKELY
    score = record.get("preferred_score")
    if isinstance(score, int | float) and score >= _HIGH_CONFIDENCE_THRESHOLD:
        confidence = ConfidenceLevel.CONFIRMED
    return make_finding_dto(
        category=FindingCategory.CRYPTO,
        cwe=[326, 327],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=confidence,
        owasp_wstg=["WSTG-CRYP-04"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "hash_id": record.get("hash_id"),
        "hash_length": record.get("hash_length"),
        "entropy": record.get("entropy"),
        "preferred_mode": record.get("preferred_mode"),
        "preferred_score": record.get("preferred_score"),
        "preferred_hashcat_id": record.get("preferred_hashcat_id"),
        "preferred_john_id": record.get("preferred_john_id"),
        "matches": record.get("matches"),
    }
    cleaned: dict[str, Any] = {
        key: value
        for key, value in payload.items()
        if value is not None and value != ""
    }
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_records(
    entries: list[dict[str, Any]], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    for index, entry in enumerate(entries):
        hash_value = _string_field(entry, "input") or _string_field(entry, "hash")
        matches_raw = entry.get("matches")
        if hash_value is None:
            _logger.debug(
                "hash_analyzer_parser.entry_missing_input",
                extra={
                    "event": "hash_analyzer_parser_entry_missing_input",
                    "tool_id": tool_id,
                    "index": index,
                },
            )
            continue
        if not isinstance(matches_raw, list) or not matches_raw:
            continue
        matches = list(_iter_matches(matches_raw))
        if not matches:
            continue
        preferred = _select_preferred(matches)
        entropy_raw = entry.get("entropy")
        entropy = (
            float(entropy_raw)
            if isinstance(entropy_raw, int | float)
            and not isinstance(entropy_raw, bool)
            else None
        )
        yield {
            "hash_id": stable_hash_12(hash_value),
            "hash_length": len(hash_value),
            "entropy": entropy,
            "preferred_mode": preferred.get("name"),
            "preferred_score": preferred.get("confidence"),
            "preferred_hashcat_id": preferred.get("hashcat"),
            "preferred_john_id": preferred.get("john"),
            "matches": matches,
        }


def _iter_matches(matches_raw: list[Any]) -> Iterator[dict[str, Any]]:
    for raw in matches_raw:
        if not isinstance(raw, dict):
            continue
        name = _string_field(raw, "name") or _string_field(raw, "algorithm")
        if name is None:
            continue
        confidence_raw = raw.get("confidence")
        confidence: float | None
        if isinstance(confidence_raw, int | float) and not isinstance(
            confidence_raw, bool
        ):
            confidence = float(confidence_raw)
        else:
            confidence = None
        hashcat_id_raw = raw.get("hashcat")
        hashcat_id: int | None
        if isinstance(hashcat_id_raw, int) and not isinstance(hashcat_id_raw, bool):
            hashcat_id = hashcat_id_raw
        else:
            hashcat_id = None
        yield {
            "name": name,
            "confidence": confidence,
            "hashcat": hashcat_id,
            "john": _string_field(raw, "john"),
        }


def _select_preferred(matches: list[dict[str, Any]]) -> dict[str, Any]:
    def _key(match: dict[str, Any]) -> tuple[float, int]:
        confidence = match.get("confidence")
        score = float(confidence) if isinstance(confidence, int | float) else 0.0
        hashcat = match.get("hashcat")
        hashcat_priority = (
            hashcat
            if isinstance(hashcat, int) and not isinstance(hashcat, bool)
            else 99_999
        )
        return (-score, hashcat_priority)

    return sorted(matches, key=_key)[0]


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_hash_analyzer_json",
]
