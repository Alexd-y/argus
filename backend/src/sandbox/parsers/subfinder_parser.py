"""Parser for ``subfinder -oJ`` output (ARG-032 batch 4b).

ProjectDiscovery's subfinder writes one JSON object per line when
invoked with ``-oJ /out/subfinder.json``::

    {"host": "api.example.com", "input": "example.com",
     "source": "crtsh"}

When invoked without ``-oJ`` the wrapper yields a list of bare
hostnames, one per line.  This parser tolerates both shapes.

Translation rules
-----------------

* One INFO finding per unique hostname (CWE-200 / CWE-668).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import FindingDTO
from src.sandbox.parsers._base import (
    safe_decode,
    safe_load_json,
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import (
    persist_jsonl_sidecar,
    safe_join_artifact,
)
from src.sandbox.parsers._subdomain_base import (
    build_subdomain_finding,
    is_valid_hostname,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "subfinder_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "subfinder.json"
_MAX_FINDINGS: Final[int] = 5_000


_DedupKey: TypeAlias = tuple[str]


def parse_subfinder(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate subfinder output (JSONL or plain) into FindingDTOs."""
    del stderr
    raw = _resolve_bytes(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if not raw:
        return []
    text = safe_decode(raw, limit=25 * 1024 * 1024)
    if not text:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for record in _iter_lines(text, tool_id=tool_id):
        host = record.get("host", "").strip().lower()
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
            "input": record.get("input", "") or "",
            "source": record.get("source", "") or "",
            "fingerprint_hash": stable_hash_12(host),
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "subfinder.cap_reached",
                extra={
                    "event": "subfinder_cap_reached",
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


def _resolve_bytes(*, stdout: bytes, artifacts_dir: Path, tool_id: str) -> bytes:
    artifact = safe_join_artifact(artifacts_dir, _CANONICAL_FILENAME)
    if artifact is not None and artifact.is_file():
        try:
            data = artifact.read_bytes()
            if data.strip():
                return data
        except OSError as exc:
            _logger.warning(
                "subfinder.artifact_unreadable",
                extra={
                    "event": "subfinder_artifact_unreadable",
                    "tool_id": tool_id,
                    "path": str(artifact),
                    "error_type": type(exc).__name__,
                },
            )
    return stdout


def _iter_lines(text: str, *, tool_id: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("{") or line.startswith("["):
            payload = safe_load_json(line.encode("utf-8"), tool_id=tool_id)
            for item in _flatten_json(payload):
                out.append(item)
            continue
        out.append({"host": line})
    return out


def _flatten_json(payload: Any) -> list[dict[str, str]]:
    if isinstance(payload, dict):
        return [_normalise_record(payload)]
    if isinstance(payload, list):
        result: list[dict[str, str]] = []
        for item in payload:
            if isinstance(item, dict):
                result.append(_normalise_record(item))
        return result
    return []


def _normalise_record(record: dict[str, Any]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key in ("host", "input", "source"):
        value = record.get(key)
        if isinstance(value, str):
            out[key] = value
    return out


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_subfinder",
]
