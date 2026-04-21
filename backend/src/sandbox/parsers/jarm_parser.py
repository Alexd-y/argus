"""Parser for ``jarm -j`` JSON output (Backlog §4.4 — ARG-029).

JARM emits a TLS-server fingerprint per scanned target.  Three
upstream shapes are tolerated:

* JSON array of records  — modern wrapper (``jarm -j``).
* Single record object   — when only one target was provided.
* JSONL file             — some operator wrappers redirect newline-
  delimited JSON to ``jarm.json``.

Each record carries (at minimum)::

    {
      "host":  "example.com",
      "port":  443,
      "jarm":  "27d40d40d29d40d1dc42d43d00041d4689ee210389f4f6b4b5b1b099f3aef84",
      "scheme":"https"
    }

A JARM hash full of zeros indicates the host did not respond on
443/TLS — these are dropped.

Translation rules
-----------------

* Every successful fingerprint becomes one INFO finding tagged
  :class:`FindingCategory.INFO` (CWE-200) with confidence
  :class:`ConfidenceLevel.CONFIRMED` — JARM hashes are deterministic.
* Severity stays ``info``; CVSS = 0.0.
* The 62-character JARM hash itself is preserved verbatim in the
  sidecar (it is not sensitive — it identifies a TLS stack, not a
  secret).
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    MAX_STDOUT_BYTES,
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    safe_decode,
    safe_load_json,
    safe_load_jsonl,
)
from src.sandbox.parsers._jsonl_base import (
    persist_jsonl_sidecar,
    safe_join_artifact,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "jarm_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "jarm.json"
_MAX_FINDINGS: Final[int] = 5_000
_JARM_FINGERPRINT_RE: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{62}$")
_EMPTY_JARM: Final[str] = "0" * 62


DedupKey: TypeAlias = tuple[str, str, str]


def parse_jarm_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate jarm output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if not payload:
        return []
    records = list(_iter_records(payload, tool_id=tool_id))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


def _load_payload(
    *, stdout: bytes, artifacts_dir: Path, tool_id: str
) -> list[dict[str, Any]]:
    artifact_path = safe_join_artifact(artifacts_dir, _CANONICAL_FILENAME)
    raw = b""
    if artifact_path is not None and artifact_path.is_file():
        try:
            raw = artifact_path.read_bytes()
        except OSError as exc:
            _logger.warning(
                "jarm_parser.artifact_unreadable",
                extra={
                    "event": "jarm_parser_artifact_unreadable",
                    "tool_id": tool_id,
                    "path": str(artifact_path),
                    "error": str(exc),
                },
            )
    if not raw:
        raw = stdout or b""
    if not raw:
        return []
    text = safe_decode(raw, limit=MAX_STDOUT_BYTES)
    stripped = text.lstrip()
    encoded = text.encode("utf-8")
    if stripped.startswith("["):
        decoded = safe_load_json(encoded, tool_id=tool_id)
        if isinstance(decoded, list):
            return [item for item in decoded if isinstance(item, dict)]
        return []
    if stripped.startswith("{") and "\n" not in stripped.rstrip():
        decoded = safe_load_json(encoded, tool_id=tool_id)
        if isinstance(decoded, dict):
            return [decoded]
        return []
    if stripped.startswith("{") and _is_single_json_object(encoded, tool_id=tool_id):
        decoded = safe_load_json(encoded, tool_id=tool_id)
        if isinstance(decoded, dict):
            return [decoded]
        return []
    return [
        record
        for record in safe_load_jsonl(encoded, tool_id=tool_id)
        if isinstance(record, dict)
    ]


def _is_single_json_object(encoded: bytes, *, tool_id: str) -> bool:
    """Return True if ``encoded`` is exactly one JSON object (no JSONL stream)."""
    try:
        json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _logger.debug(
            "jarm_parser.single_object_probe_failed",
            extra={
                "event": "jarm_parser_single_object_probe_failed",
                "tool_id": tool_id,
            },
        )
        return False
    return True


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[str, str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            str(record.get("host") or ""),
            str(record.get("port") or ""),
            str(record.get("jarm") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding()
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            str(record.get("host") or ""),
            str(record.get("port") or ""),
            str(record.get("jarm") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "jarm_parser.cap_reached",
                extra={
                    "event": "jarm_parser_cap_reached",
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
        category=FindingCategory.INFO,
        cwe=[200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-02", "WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "host": record.get("host"),
        "port": record.get("port"),
        "scheme": record.get("scheme"),
        "jarm": record.get("jarm"),
    }
    cleaned: dict[str, Any] = {
        key: value
        for key, value in payload.items()
        if value is not None and value != ""
    }
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_records(
    records: list[dict[str, Any]], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    for index, raw in enumerate(records):
        host = (
            _string_field(raw, "host")
            or _string_field(raw, "target")
            or _string_field(raw, "domain")
        )
        if host is None:
            _logger.debug(
                "jarm_parser.entry_missing_host",
                extra={
                    "event": "jarm_parser_entry_missing_host",
                    "tool_id": tool_id,
                    "index": index,
                },
            )
            continue
        port = _coerce_port(raw.get("port"))
        if port is None:
            port = 443
        fingerprint = (
            _string_field(raw, "jarm")
            or _string_field(raw, "jarm_fingerprint")
            or _string_field(raw, "fingerprint")
        )
        if fingerprint is None or not _is_valid_jarm(fingerprint):
            _logger.debug(
                "jarm_parser.entry_skipped_invalid",
                extra={
                    "event": "jarm_parser_entry_skipped_invalid",
                    "tool_id": tool_id,
                    "host": host,
                    "port": port,
                },
            )
            continue
        yield {
            "host": host,
            "port": port,
            "scheme": _string_field(raw, "scheme") or "https",
            "jarm": fingerprint.lower(),
        }


def _coerce_port(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if 0 < value < 65_536:
            return value
        return None
    if isinstance(value, str):
        try:
            port = int(value.strip())
        except ValueError:
            return None
        if 0 < port < 65_536:
            return port
    return None


def _is_valid_jarm(fingerprint: str) -> bool:
    candidate = fingerprint.strip().lower()
    if candidate == _EMPTY_JARM:
        return False
    return bool(_JARM_FINGERPRINT_RE.match(candidate))


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_jarm_json",
]


def _typecheck_iterator() -> None:  # pragma: no cover - mypy seam
    _: Iterator[dict[str, Any]] = iter([])
    del _
