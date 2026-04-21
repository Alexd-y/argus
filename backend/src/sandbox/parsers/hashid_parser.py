"""Parser for ``hashid -j`` JSON output (Backlog §4.13 — ARG-029).

``hashid -m -j hashes.txt`` emits a JSON array describing each input
line.  Empirically (the project ships an open-source clone) the
shape is::

    [
      {
        "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
        "modes": [
          {"name": "MD5", "hashcat": 0, "john": "raw-md5"},
          {"name": "MD4", "hashcat": null, "john": "raw-md4"}
        ]
      },
      {
        "hash": "21BD12DC183F740EE76F27B78EB39C8AD972A757",
        "modes": [
          {"name": "SHA-1", "hashcat": 100, "john": "raw-sha1"}
        ]
      }
    ]

We emit one INFO finding per ``(hash, top-mode)`` pair so the operator
can route the candidate cracker without re-parsing.  The raw hash is
NEVER persisted in cleartext — only ``stable_hash_12`` is stored, plus
a length-bucket and modes.

Translation rules
-----------------

* Category :class:`FindingCategory.CRYPTO` with CWE-326 (inadequate
  encryption strength) — a hash exposed for cracking IS a crypto
  artefact; the severity stays ``info`` because identification alone
  is not a vulnerability.
* Confidence :class:`ConfidenceLevel.LIKELY` — hashid relies on
  prefix/length heuristics.
* If a record exposes only a single high-confidence mode (NTLM,
  bcrypt, Argon2, PBKDF2) the parser tags ``preferred_mode`` so the
  cracker pipeline can pick a good default.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "hashid_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "hashid.json"
_MAX_FINDINGS: Final[int] = 5_000


_PREFERRED_HASHCAT_MODES: Final[frozenset[int]] = frozenset(
    {1000, 1100, 1500, 1600, 1700, 1800, 3200, 5500, 5600, 7400, 9900}
)


DedupKey: TypeAlias = tuple[str, str]


def parse_hashid_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate hashid -j output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if payload is None:
        return []
    if not isinstance(payload, list):
        _logger.warning(
            "hashid_parser.payload_not_array",
            extra={
                "event": "hashid_parser_payload_not_array",
                "tool_id": tool_id,
                "actual_type": type(payload).__name__,
            },
        )
        return []
    records = list(_iter_records(payload, tool_id=tool_id))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


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
        finding = _build_finding()
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            str(record.get("hash_id") or ""),
            str(record.get("preferred_mode") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "hashid_parser.cap_reached",
                extra={
                    "event": "hashid_parser_cap_reached",
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


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.CRYPTO,
        cwe=[326],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.LIKELY,
        owasp_wstg=["WSTG-CRYP-04"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "hash_id": record.get("hash_id"),
        "hash_length": record.get("hash_length"),
        "preferred_mode": record.get("preferred_mode"),
        "preferred_hashcat_id": record.get("preferred_hashcat_id"),
        "preferred_john_id": record.get("preferred_john_id"),
        "modes": record.get("modes"),
    }
    cleaned: dict[str, Any] = {
        key: value
        for key, value in payload.items()
        if value is not None and value != ""
    }
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_records(payload: list[Any], *, tool_id: str) -> Iterable[dict[str, Any]]:
    for index, raw in enumerate(payload):
        if not isinstance(raw, dict):
            _logger.debug(
                "hashid_parser.entry_not_object",
                extra={
                    "event": "hashid_parser_entry_not_object",
                    "tool_id": tool_id,
                    "index": index,
                },
            )
            continue
        hash_value = _string_field(raw, "hash")
        modes_raw = raw.get("modes")
        if not isinstance(modes_raw, list) or not modes_raw:
            continue
        modes = list(_iter_modes(modes_raw))
        if not modes:
            continue
        preferred = _select_preferred(modes)
        yield {
            "hash_id": stable_hash_12(hash_value or "") if hash_value else "",
            "hash_length": len(hash_value) if hash_value else None,
            "preferred_mode": preferred.get("name"),
            "preferred_hashcat_id": preferred.get("hashcat"),
            "preferred_john_id": preferred.get("john"),
            "modes": modes,
        }


def _iter_modes(modes_raw: list[Any]) -> Iterator[dict[str, Any]]:
    for raw in modes_raw:
        if not isinstance(raw, dict):
            continue
        name = _string_field(raw, "name")
        if name is None:
            continue
        hashcat_id_raw = raw.get("hashcat")
        hashcat_id: int | None
        if isinstance(hashcat_id_raw, int) and not isinstance(hashcat_id_raw, bool):
            hashcat_id = hashcat_id_raw
        else:
            hashcat_id = None
        john_id = _string_field(raw, "john")
        yield {
            "name": name,
            "hashcat": hashcat_id,
            "john": john_id,
        }


def _select_preferred(modes: list[dict[str, Any]]) -> dict[str, Any]:
    for mode in modes:
        hashcat_id = mode.get("hashcat")
        if isinstance(hashcat_id, int) and hashcat_id in _PREFERRED_HASHCAT_MODES:
            return mode
    return modes[0]


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_hashid_json",
]
