"""Parser for ``unicornscan`` text output (ARG-032 batch 4c).

Unicornscan writes a flat ``host:port[state] - protocol`` style log to
``-o /out/unicornscan.txt``.  Canonical line shape::

    TCP open                  http[   80]    from 10.0.0.1   ttl 64
    TCP open                  https[  443]   from 10.0.0.1   ttl 64
    UDP open                  domain[  53]   from 10.0.0.2

Findings:

* One INFO finding per ``(host, port, proto)`` tuple — open ports are
  high-signal but rarely a vulnerability on their own.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Final, TypeAlias

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
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "unicornscan_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("unicornscan.txt", "unicornscan.log")
_MAX_FINDINGS: Final[int] = 50_000

# Canonical unicornscan ``open`` line:
#   ``TCP open  http[80]  from 10.0.0.1 ttl 64``
_OPEN_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<proto>TCP|UDP)\s+open\s+"
    r"(?P<service>[a-zA-Z0-9_\-]+)\s*\[\s*(?P<port>\d+)\s*\]"
    r"\s+from\s+(?P<host>\S+)"
    r"(?:\s+ttl\s+(?P<ttl>\d+))?",
    re.IGNORECASE,
)


_DedupKey: TypeAlias = tuple[str, int, str]


def parse_unicornscan(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate unicornscan text output into INFO open-port FindingDTOs."""
    del stderr
    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=_CANONICAL_NAMES,
        tool_id=tool_id,
    )
    if not text:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for record in _iter_open_ports(text):
        host = str(record["host"])
        proto = str(record["proto"])
        port_value = record["port"]
        if not isinstance(port_value, int):
            continue
        key: _DedupKey = (host, port_value, proto)
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding()
        evidence = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "unicornscan.cap_reached",
                extra={
                    "event": "unicornscan_cap_reached",
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


def _iter_open_ports(text: str) -> Iterator[dict[str, object]]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _OPEN_RE.search(line)
        if match is None:
            continue
        try:
            port = int(match.group("port"))
        except (TypeError, ValueError):
            continue
        if not (0 < port < 65_536):
            continue
        yield {
            "proto": match.group("proto").lower(),
            "host": match.group("host").strip().lower(),
            "port": port,
            "service": match.group("service").strip().lower(),
            "ttl": match.group("ttl") or "",
        }


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200, 668],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-02", "WSTG-INFO-04"],
    )


def _build_evidence(record: dict[str, object], *, tool_id: str) -> str:
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "host": record["host"],
        "port": record["port"],
        "proto": record["proto"],
        "service": record["service"],
        "ttl": record["ttl"],
        "fingerprint_hash": stable_hash_12(
            f"unicornscan|{record['host']}|{record['port']}|{record['proto']}"
        ),
    }
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_unicornscan",
]
