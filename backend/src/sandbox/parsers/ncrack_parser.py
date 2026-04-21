"""Parser for ``ncrack`` text output (ARG-032 batch 4c).

Ncrack writes ``Discovered credentials`` blocks to ``-oN /out/ncrack.txt``.
Canonical block shape::

    Discovered credentials on ssh://10.0.0.1:22
        10.0.0.1 22/tcp ssh: 'root' 'toor'

CRITICAL security gate
----------------------

The password value is **redacted before** the FindingDTO is built and
**never** appears in the sidecar.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Final, TypeAlias

from src.pipeline.contracts.finding_dto import FindingDTO
from src.sandbox.parsers._credential_base import (
    build_credential_evidence,
    build_credential_finding,
)
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "ncrack_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("ncrack.txt", "ncrack.log")
_MAX_FINDINGS: Final[int] = 1_000

# Match either ``Discovered credentials on <svc>://<host>:<port>`` or the
# inner ``<host> <port>/<proto> <svc>: '<user>' '<pass>'`` line shape.
_INNER_CRED_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<host>\S+)\s+(?P<port>\d+)/(?P<proto>\w+)\s+"
    r"(?P<service>[\w\-]+):\s+"
    r"'(?P<user>[^']*)'\s+'(?P<password>[^']*)'",
)


_DedupKey: TypeAlias = tuple[str, str, str]


def parse_ncrack(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate ncrack text output into AUTH FindingDTOs."""
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

    for record in _iter_credentials(text):
        key: _DedupKey = (record["host"], record["service"], record["username"])
        if key in seen:
            continue
        seen.add(key)
        finding = build_credential_finding()
        evidence = build_credential_evidence(
            tool_id=tool_id,
            host=record["host"],
            service=record["service"],
            username=record["username"],
            password_length=int(record["password_length"]),
            extra={"port": record["port"], "proto": record["proto"]},
        )
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "ncrack.cap_reached",
                extra={
                    "event": "ncrack_cap_reached",
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


def _iter_credentials(text: str) -> Iterator[dict[str, str]]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _INNER_CRED_RE.search(line)
        if match is None:
            continue
        password = match.group("password")
        user = match.group("user")
        if not user:
            continue
        yield {
            "host": match.group("host").strip(),
            "port": match.group("port"),
            "proto": match.group("proto").lower(),
            "service": match.group("service").strip(),
            "username": user.strip(),
            "password_length": str(len(password)),
        }


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_ncrack",
]
