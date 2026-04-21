"""Parser for ``assetfinder --subs-only`` output (ARG-032 batch 4b).

assetfinder writes one subdomain per line to ``/out/assetfinder.txt``::

    api.example.com
    www.example.com
    cdn.example.com

Translation rules
-----------------

* One INFO finding per unique hostname (CWE-200 / CWE-668).
* Strict RFC-1035 validation guarantees noisy log lines never become
  findings.
"""

from __future__ import annotations

import json
import logging
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


EVIDENCE_SIDECAR_NAME: Final[str] = "assetfinder_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = (
    "assetfinder.txt",
    "assetfinder.log",
)
_MAX_FINDINGS: Final[int] = 5_000


_DedupKey: TypeAlias = tuple[str]


def parse_assetfinder(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate assetfinder text output into FindingDTOs."""
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

    for raw_line in text.splitlines():
        host = raw_line.strip().lower()
        if not host or not is_valid_hostname(host):
            continue
        key: _DedupKey = (host,)
        if key in seen:
            continue
        seen.add(key)
        finding = build_subdomain_finding()
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "host": host,
            "fingerprint_hash": stable_hash_12(host),
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "assetfinder.cap_reached",
                extra={
                    "event": "assetfinder_cap_reached",
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


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_assetfinder",
]
