"""Parser for ``naabu -json`` output (Backlog/dev1_md §4.2 — ARG-029).

ProjectDiscovery naabu performs a TCP-SYN port discovery sweep and emits
JSONL — one open port per line:

.. code-block:: json

    {"host":"example.com", "ip":"104.16.99.52", "port":443, "protocol":"tcp",
     "tls": true, "timestamp": "2026-04-19T11:00:00Z"}
    {"host":"example.com", "ip":"104.16.99.52", "port":80, "protocol":"tcp",
     "tls": false, "timestamp": "2026-04-19T11:00:00Z"}

The catalog wires it as ``naabu -host {ip} -p - -json -o
{out_dir}/naabu.json`` so the canonical artefact is JSONL on disk.

Translation rules
-----------------

* **Category** — :class:`FindingCategory.INFO` for every record.  An
  open port by itself is intelligence, not a vulnerability; downstream
  Nmap / Nuclei runs convert ports into actionable findings.

* **Severity / CVSS** — pinned to the sentinel ``info`` band (CVSS 0.0,
  AV:N/AC:L/PR:N/UI:N/C:N/I:N/A:N).  Naabu is a discovery tool; the
  finding only states "this port responded to a SYN".

* **Confidence** — :class:`ConfidenceLevel.CONFIRMED`.  A SYN/ACK is
  binary evidence the port is open; no further inference required.

* **CWE** — pinned at ``[200, 668]`` (Information Exposure +
  Exposure of Resource to Wrong Sphere) per the YAML descriptor.

Dedup
-----

``(ip, port, protocol)`` — the same port reported via a host and an IP
collapse onto a single finding.  Callers who want both surface forms
should inspect the sidecar.

Sidecar
-------

Mirrored into ``artifacts_dir / "naabu_findings.jsonl"`` with one
record per open port carrying ``host`` / ``ip`` / ``port`` /
``protocol`` / ``tls`` / ``timestamp``.
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
)
from src.sandbox.parsers._jsonl_base import (
    iter_jsonl_records,
    persist_jsonl_sidecar,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "naabu_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "naabu.json"
_MAX_FINDINGS: Final[int] = 100_000


DedupKey: TypeAlias = tuple[str, int, str]


def parse_naabu_jsonl(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate naabu ``-json`` output into INFO open-port findings."""
    del stderr
    records = list(
        _iter_normalised(
            iter_jsonl_records(
                stdout=stdout,
                artifacts_dir=artifacts_dir,
                canonical_name=_CANONICAL_FILENAME,
                tool_id=tool_id,
            ),
            tool_id=tool_id,
        )
    )
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
            str(record.get("ip") or record.get("host") or ""),
            int(record.get("port") or 0),
            str(record.get("protocol") or "tcp"),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding()
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "naabu_parser.cap_reached",
                extra={
                    "event": "naabu_parser_cap_reached",
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
        "kind": "naabu",
        "host": record.get("host"),
        "ip": record.get("ip"),
        "port": record.get("port"),
        "protocol": record.get("protocol") or "tcp",
        "tls": record.get("tls"),
        "timestamp": record.get("timestamp"),
    }
    cleaned = {key: value for key, value in payload.items() if value not in (None, "")}
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_normalised(
    raw_records: Iterator[dict[str, Any]],
    *,
    tool_id: str,
) -> Iterator[dict[str, Any]]:
    for raw in raw_records:
        port = _coerce_int(raw.get("port"))
        if port is None or not (0 < port <= 65535):
            _logger.warning(
                "naabu_parser.invalid_port",
                extra={
                    "event": "naabu_parser_invalid_port",
                    "tool_id": tool_id,
                    "raw_port": raw.get("port"),
                },
            )
            continue
        ip = _string_field(raw, "ip")
        host = _string_field(raw, "host")
        if not ip and not host:
            continue
        yield {
            "host": host,
            "ip": ip,
            "port": port,
            "protocol": _string_field(raw, "protocol") or "tcp",
            "tls": _coerce_bool(raw.get("tls")),
            "timestamp": _string_field(raw, "timestamp"),
        }


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


def _coerce_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes"}:
            return True
        if lowered in {"false", "0", "no"}:
            return False
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_naabu_jsonl",
]
