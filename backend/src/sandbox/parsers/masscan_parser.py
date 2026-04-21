"""Parser for ``masscan -oJ`` output (Backlog/dev1_md §4.2 — ARG-029).

masscan emits a single top-level JSON array — one object per open
port observation:

.. code-block:: json

    [
      {"ip":"10.0.0.100", "timestamp":"1516653779",
       "ports":[{"port":22, "proto":"tcp", "status":"open",
                 "reason":"syn-ack", "ttl":128}]},
      {"ip":"10.0.0.100", "timestamp":"1516653780",
       "ports":[{"port":80, "proto":"tcp", "status":"open",
                 "reason":"syn-ack", "ttl":128}]}
    ]

masscan is grouped under JSON_LINES in the ARG-029 plan because it
shares the discovery / open-port semantics of naabu, but the wire
format is a JSON array (the YAML descriptor declares
``parse_strategy: json_object``).  This parser handles both shapes
defensively — older masscan releases occasionally produced trailing-
comma-broken JSON; we strip the trailing comma + close-bracket if the
top level fails the strict parse.

Translation rules
-----------------

* **Category** — :class:`FindingCategory.INFO` for every record.
* **Severity / CVSS** — pinned to the sentinel ``info`` band (CVSS
  0.0).  Only ``status=="open"`` records are emitted; ``filtered``
  / ``closed`` are dropped.
* **Confidence** — :class:`ConfidenceLevel.CONFIRMED`.
* **CWE** — pinned at ``[200, 668]`` per the YAML descriptor.

Dedup key
---------

``(ip, port, proto)`` so the same port observed multiple times
collapses to a single finding.

Sidecar
-------

Mirrored into ``artifacts_dir / "masscan_findings.jsonl"`` with one
record per open port (``ip`` / ``port`` / ``proto`` / ``status`` /
``reason`` / ``ttl`` / ``timestamp``).
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
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
    safe_load_json,
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
    safe_join_artifact,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "masscan_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "masscan.json"
_MAX_FINDINGS: Final[int] = 100_000


DedupKey: TypeAlias = tuple[str, int, str]


def parse_masscan_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate masscan ``-oJ`` output into INFO open-port findings."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if not isinstance(payload, list):
        if payload is not None:
            _logger.warning(
                "masscan_parser.envelope_not_list",
                extra={
                    "event": "masscan_parser_envelope_not_list",
                    "tool_id": tool_id,
                    "actual_type": type(payload).__name__,
                },
            )
        return []
    records = list(_iter_normalised(payload, tool_id=tool_id))
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
    keyed: list[tuple[DedupKey, FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            str(record.get("ip") or ""),
            int(record.get("port") or 0),
            str(record.get("proto") or "tcp"),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding()
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "masscan_parser.cap_reached",
                extra={
                    "event": "masscan_parser_cap_reached",
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
        cwe=[200, 668],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-02"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "masscan",
        "ip": record.get("ip"),
        "port": record.get("port"),
        "proto": record.get("proto"),
        "status": record.get("status"),
        "reason": record.get("reason"),
        "ttl": record.get("ttl"),
        "timestamp": record.get("timestamp"),
    }
    cleaned = {key: value for key, value in payload.items() if value not in (None, "")}
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_normalised(payload: list[Any], *, tool_id: str) -> Iterator[dict[str, Any]]:
    for raw in payload:
        if not isinstance(raw, dict):
            continue
        ip = _string_field(raw, "ip")
        if ip is None:
            continue
        timestamp = _string_field(raw, "timestamp")
        ports = raw.get("ports")
        if not isinstance(ports, list):
            continue
        for entry in ports:
            if not isinstance(entry, dict):
                continue
            status = _string_field(entry, "status")
            if status and status.lower() != "open":
                continue
            port = _coerce_int(entry.get("port"))
            if port is None or not (0 < port <= 65535):
                _logger.warning(
                    "masscan_parser.invalid_port",
                    extra={
                        "event": "masscan_parser_invalid_port",
                        "tool_id": tool_id,
                        "raw_port": entry.get("port"),
                    },
                )
                continue
            yield {
                "ip": ip,
                "port": port,
                "proto": (_string_field(entry, "proto") or "tcp").lower(),
                "status": status or "open",
                "reason": _string_field(entry, "reason"),
                "ttl": _coerce_int(entry.get("ttl")),
                "timestamp": timestamp,
            }


def _load_payload(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> Any:
    """Resolve masscan output, with a one-shot trailing-comma repair.

    Older masscan versions occasionally close the array with a trailing
    comma (``[..., ]``) which makes the JSON invalid.  We fall back to
    stripping a single trailing ``,]`` pair and reparsing — this is a
    one-byte tactical fix and never modifies record content.
    """
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if payload is not None:
        return payload
    raw = _read_repair_source(
        stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id
    )
    if not raw:
        return None
    repaired = _repair_trailing_comma(raw)
    if repaired is None:
        return None
    return safe_load_json(repaired, tool_id=tool_id)


def _read_repair_source(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> bytes:
    canonical = safe_join_artifact(artifacts_dir, _CANONICAL_FILENAME)
    if canonical is not None and canonical.is_file():
        try:
            return canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "masscan_parser.canonical_read_failed",
                extra={
                    "event": "masscan_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "error_type": type(exc).__name__,
                },
            )
    return stdout


def _repair_trailing_comma(raw: bytes) -> bytes | None:
    """Remove a single trailing ``,]`` pair (older masscan bug)."""
    stripped = raw.strip()
    if not stripped.endswith(b"]"):
        return None
    inner = stripped[:-1].rstrip()
    if inner.endswith(b","):
        return inner[:-1] + b"]"
    return None


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_masscan_json",
]
