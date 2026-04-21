"""Parser for ``webanalyze -output json`` output (ARG-032 batch 4a).

webanalyze (Wappalyzer Go-port) emits a JSON array (or single record)
of detected technologies per scanned host::

    [
      {
        "hostname": "example.com",
        "matches": [
          {
            "app_name":   "Apache",
            "version":    "2.4.41",
            "confidence": 100,
            "categories": ["Web servers"]
          },
          ...
        ]
      }
    ]

Translation rules
-----------------

* One INFO finding per unique ``(hostname, app_name, major_version)``
  (CWE-200) — the technology fingerprint feeds the §4.7 / §4.8
  vulnerability scanner planner.
* Confidence ladder: ``confidence >= 75`` → :class:`ConfidenceLevel.CONFIRMED`,
  ``>= 50`` → ``LIKELY``, otherwise ``SUSPECTED``.
* No secret material is touched; ``hostname`` and ``app_name`` are
  preserved verbatim (after :func:`scrub_evidence_strings` for
  defence in depth).
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
from src.sandbox.parsers._jsonl_base import (
    persist_jsonl_sidecar,
    safe_join_artifact,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "webanalyze_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "webanalyze.json"
_MAX_FINDINGS: Final[int] = 1_000


_DedupKey: TypeAlias = tuple[str, str, str]


def parse_webanalyze(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate webanalyze JSON output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if not payload:
        return []
    records = list(_iter_records(payload))
    if not records:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []
    for record in records:
        hostname = _string_field(record, "hostname") or "unknown"
        for match in _iter_matches(record):
            app_name = _string_field(match, "app_name") or _string_field(match, "name")
            if not app_name:
                continue
            version = _string_field(match, "version") or ""
            major = _major_version(version)
            key: _DedupKey = (hostname, app_name, major)
            if key in seen:
                continue
            seen.add(key)
            confidence = _coerce_confidence(match.get("confidence"))
            finding = _build_finding(confidence)
            categories = _normalise_categories(match.get("categories"))
            evidence: dict[str, object] = {
                "tool_id": tool_id,
                "hostname": hostname,
                "app_name": app_name,
                "version": version,
                "major_version": major,
                "confidence": confidence.value,
                "categories": categories,
                "fingerprint_hash": stable_hash_12(f"{hostname}|{app_name}|{major}"),
            }
            keyed.append((key, finding, _serialise(evidence)))
            if len(keyed) >= _MAX_FINDINGS:
                _logger.warning(
                    "webanalyze.cap_reached",
                    extra={
                        "event": "webanalyze_cap_reached",
                        "tool_id": tool_id,
                        "cap": _MAX_FINDINGS,
                    },
                )
                break
        if len(keyed) >= _MAX_FINDINGS:
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


def _load_payload(*, stdout: bytes, artifacts_dir: Path, tool_id: str) -> Any:
    artifact = safe_join_artifact(artifacts_dir, _CANONICAL_FILENAME)
    if artifact is not None and artifact.is_file():
        try:
            raw = artifact.read_bytes()
        except OSError as exc:
            _logger.warning(
                "webanalyze.artifact_unreadable",
                extra={
                    "event": "webanalyze_artifact_unreadable",
                    "tool_id": tool_id,
                    "path": str(artifact),
                    "error_type": type(exc).__name__,
                },
            )
            raw = b""
        if raw.strip():
            return safe_load_json(raw, tool_id=tool_id)
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
        if "matches" in payload or "hostname" in payload:
            yield payload
            return
        results = payload.get("results")
        if isinstance(results, list):
            for item in results:
                if isinstance(item, dict):
                    yield item


def _iter_matches(record: dict[str, Any]) -> Iterable[dict[str, Any]]:
    matches = record.get("matches")
    if isinstance(matches, list):
        for item in matches:
            if isinstance(item, dict):
                yield item


def _major_version(version: str) -> str:
    if not version:
        return ""
    head = version.split(".", 1)[0]
    return head.strip()


def _coerce_confidence(value: Any) -> ConfidenceLevel:
    try:
        score = int(value)
    except (TypeError, ValueError):
        return ConfidenceLevel.SUSPECTED
    if score >= 75:
        return ConfidenceLevel.CONFIRMED
    if score >= 50:
        return ConfidenceLevel.LIKELY
    return ConfidenceLevel.SUSPECTED


def _normalise_categories(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    return sorted(set(out))


def _build_finding(confidence: ConfidenceLevel) -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=confidence,
        owasp_wstg=["WSTG-INFO-02", "WSTG-INFO-08"],
    )


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
    "parse_webanalyze",
]
