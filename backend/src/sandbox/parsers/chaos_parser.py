"""Parser for ``chaos`` (ProjectDiscovery) text output (ARG-032 batch 4c).

ProjectDiscovery's ``chaos -d <domain> -o /out/chaos.txt`` returns a
plain newline-delimited list of subdomains discovered against the
target domain.  Canonical line shape::

    api.example.com
    cdn.example.com
    *.dev.example.com
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Final, TypeAlias

from src.pipeline.contracts.finding_dto import FindingDTO
from src.sandbox.parsers._base import stable_hash_12
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._subdomain_base import (
    build_subdomain_finding,
    is_valid_hostname,
)
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "chaos_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("chaos.txt", "chaos.log")
_MAX_FINDINGS: Final[int] = 50_000


_DedupKey: TypeAlias = str


def parse_chaos(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate chaos plaintext into INFO subdomain FindingDTOs."""
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

    for host in _iter_hostnames(text):
        if host in seen:
            continue
        seen.add(host)
        finding = build_subdomain_finding()
        evidence = _build_evidence(host, tool_id=tool_id)
        keyed.append((host, finding, evidence))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "chaos.cap_reached",
                extra={
                    "event": "chaos_cap_reached",
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


def _iter_hostnames(text: str) -> Iterator[str]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # ``chaos`` may emit wildcard hostnames like ``*.dev.example.com`` —
        # strip the leading wildcard and validate the remaining label
        # set as a regular hostname.
        candidate = line.lstrip("*.").strip()
        if not is_valid_hostname(candidate):
            continue
        yield candidate.lower()


def _build_evidence(host: str, *, tool_id: str) -> str:
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "host": host,
        "fingerprint_hash": stable_hash_12(f"chaos|{host}"),
    }
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_chaos",
]
