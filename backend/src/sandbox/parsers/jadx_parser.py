"""Parser for ``jadx`` decompilation log (ARG-032 batch 4b).

The catalog ``jadx`` tool decompiles an APK / DEX into Java sources
under ``/out/jadx/`` and writes a progress log at ``/out/jadx.log``.
Canonical line shape::

    INFO  - loading ...
    INFO  - processing ...
    WARN  - failed to decompile method 'X' in class 'Y'
    ERROR - failed to decompile class 'Z'

Translation rules
-----------------

* One INFO finding per ``WARN`` / ``ERROR`` log line (CWE-1059) keyed
  on ``(level, hash_of_message)``.
* One INFO finding per ``loading X.apk`` line (CWE-200) — surfaces
  the artefact actually decompiled.

Memory addresses found in stack traces are scrubbed via
:func:`scrub_evidence_strings` before sidecar persistence.
"""

from __future__ import annotations

import json
import logging
import re
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
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "jadx_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("jadx.log", "jadx.txt")
_MAX_FINDINGS: Final[int] = 500

_LOG_LEVEL_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<level>INFO|WARN|ERROR|DEBUG)\s*[-:]\s*(?P<message>.+)$",
    re.IGNORECASE,
)
_LOAD_RE: Final[re.Pattern[str]] = re.compile(
    r"loading\s+(?P<path>\S+\.(?:apk|dex|jar))",
    re.IGNORECASE,
)


_DedupKey: TypeAlias = tuple[str, str]


def parse_jadx(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate jadx log into FindingDTOs."""
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

    for record in _iter_records(text):
        key: _DedupKey = (record["kind"], record["fingerprint"])
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record["kind"])
        keyed.append((key, finding, _serialise_evidence(record, tool_id=tool_id)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "jadx.cap_reached",
                extra={
                    "event": "jadx_cap_reached",
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


def _iter_records(text: str) -> Iterator[dict[str, str]]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        load_match = _LOAD_RE.search(line)
        if load_match is not None:
            path = load_match.group("path")
            yield {
                "kind": "artifact_loaded",
                "fingerprint": stable_hash_12(path),
                "path": path,
                "evidence": line[:200],
            }
            continue
        log_match = _LOG_LEVEL_RE.match(line)
        if log_match is None:
            continue
        level = log_match.group("level").upper()
        if level not in {"WARN", "ERROR"}:
            continue
        message = log_match.group("message").strip()
        if not message:
            continue
        yield {
            "kind": f"log_{level.lower()}",
            "fingerprint": stable_hash_12(f"{level}|{message}"),
            "level": level,
            "evidence": message[:200],
        }


def _build_finding(kind: str) -> FindingDTO:
    if kind == "artifact_loaded":
        return make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[200],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.CONFIRMED,
            owasp_wstg=["WSTG-INFO-02"],
        )
    if kind == "log_error":
        return make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[1059, 755],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.LIKELY,
            owasp_wstg=["WSTG-ERRH-02"],
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[1059],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.SUSPECTED,
        owasp_wstg=["WSTG-INFO-02"],
    )


def _serialise_evidence(record: dict[str, str], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "synthetic_id": stable_hash_12(
            f"{record.get('kind', '')}::{record.get('fingerprint', '')}"
        ),
        **record,
    }
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_jadx",
]
