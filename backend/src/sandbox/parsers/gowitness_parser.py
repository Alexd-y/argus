"""Parser for gowitness screenshot output (ARG-032 batch 4a).

The catalog ``gowitness`` tool drops a directory of PNG screenshots
plus a ``screenshots.json`` (or ``index.json``) manifest at
``/out/screens/`` describing each captured URL::

    [
      {
        "url":        "https://example.com",
        "title":      "Example Domain",
        "status":     200,
        "ip":         "93.184.216.34",
        "filename":   "https-example-com.png"
      },
      ...
    ]

Translation rules
-----------------

* One INFO finding per unique ``(host, status_class, title_hash)``
  manifest entry (CWE-200) — the visual triage record points
  operators at the rendered page; raster bytes themselves are NOT
  inlined into evidence.
* Title strings are run through :func:`scrub_evidence_strings`
  (defence in depth) but otherwise preserved — page titles are not
  secrets.

Fail-soft behaviour: a missing manifest / artifact dir / malformed
JSON returns ``[]`` with a structured warning.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
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
    stable_hash_12,
)
from src.sandbox.parsers._browser_base import (
    browse_artifact_dir,
    load_first_existing,
    safe_url_parts,
)
from src.sandbox.parsers._jsonl_base import (
    persist_jsonl_sidecar,
    safe_join_artifact,
)
from src.sandbox.parsers._text_base import (
    redact_password_in_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "gowitness_findings.jsonl"
_CANONICAL_DIR: Final[str] = "screens"
_MANIFEST_CANDIDATES: Final[tuple[str, ...]] = (
    "screenshots.json",
    "gowitness.json",
    "index.json",
)
_MAX_FINDINGS: Final[int] = 1_000


_DedupKey: TypeAlias = tuple[str, str, str]


def parse_gowitness(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate gowitness manifest output into FindingDTOs."""
    del stderr
    artifact_dir = browse_artifact_dir(artifacts_dir, _CANONICAL_DIR)
    payload = _load_payload(artifact_dir, stdout=stdout, tool_id=tool_id)
    if not payload:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []
    for record in _iter_records(payload):
        raw_url = _string_field(record, "url") or ""
        host, _ = safe_url_parts(raw_url)
        url = redact_password_in_text(raw_url)
        try:
            status = int(record.get("status") or record.get("status_code") or 0)
        except (TypeError, ValueError):
            status = 0
        title = _string_field(record, "title") or ""
        title_hash = stable_hash_12(title)
        key: _DedupKey = (host, _status_class(status), title_hash)
        if key in seen:
            continue
        seen.add(key)
        finding = make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[200],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.CONFIRMED,
            owasp_wstg=["WSTG-INFO-02", "WSTG-INFO-08"],
        )
        evidence: dict[str, object] = {
            "tool_id": tool_id,
            "host": host,
            "status": status,
            "title": title,
            "title_hash": title_hash,
            "url_hash": stable_hash_12(url),
            "screenshot_file": _safe_filename(record.get("filename")),
            "kind": "screenshot",
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "gowitness.cap_reached",
                extra={
                    "event": "gowitness_cap_reached",
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


def _load_payload(artifact_dir: Path | None, *, stdout: bytes, tool_id: str) -> Any:
    candidates: list[Path] = []
    if artifact_dir is not None:
        candidates = [
            path
            for name in _MANIFEST_CANDIDATES
            if (path := safe_join_artifact(artifact_dir, name)) is not None
        ]
    raw = load_first_existing(candidates, tool_id=tool_id)
    if raw.strip():
        decoded = safe_load_json(raw, tool_id=tool_id)
        if decoded is not None:
            return decoded
    if stdout and stdout.strip():
        return safe_load_json(stdout, tool_id=tool_id)
    return None


def _iter_records(payload: Any) -> Iterable[dict[str, Any]]:
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(payload, dict):
        rows = (
            payload.get("screenshots")
            or payload.get("results")
            or payload.get("entries")
        )
        if isinstance(rows, list):
            for item in rows:
                if isinstance(item, dict):
                    yield item
            return
        if "url" in payload or "filename" in payload:
            yield payload


def _status_class(status: int) -> str:
    if status <= 0:
        return "0xx"
    return f"{(status // 100) * 100}xx"


def _safe_filename(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_gowitness",
]
