"""Parser for WhatWeb ``--log-json`` output (ARG-032 batch 4a).

WhatWeb emits a JSON array (one record per scanned target).  Each
record carries a ``plugins`` mapping that flattens to one INFO
finding per detected technology::

    [
      {
        "target":      "http://example.com",
        "http_status": 200,
        "plugins": {
          "Apache":     {"version": ["2.4.41"]},
          "PHP":        {"string": ["7.4.3"]},
          "X-Powered-By": {"string": ["PHP/7.4.3"]},
          "Title":      {"string": ["Welcome"]}
        }
      }
    ]

Translation rules
-----------------

* One INFO finding per ``(host, plugin_name, version)`` tuple
  (CWE-200), capped at :data:`_MAX_FINDINGS`.
* Confidence is :class:`ConfidenceLevel.LIKELY` (WhatWeb level-3
  aggressive scan); the version field, when present, escalates to
  ``CONFIRMED``.
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
    safe_url_parts,
)
from src.sandbox.parsers._jsonl_base import (
    persist_jsonl_sidecar,
    safe_join_artifact,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "whatweb_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "whatweb.json"
_MAX_FINDINGS: Final[int] = 1_000
_SKIP_PLUGINS: Final[frozenset[str]] = frozenset(
    {"HTTPServer", "Title", "Country", "IP", "RedirectLocation"}
)


_DedupKey: TypeAlias = tuple[str, str, str]


def parse_whatweb(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate WhatWeb JSON output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if not payload:
        return []
    records = _normalise_payload(payload)
    if not records:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []
    for record in records:
        raw_target = _string_field(record, "target") or ""
        host_raw, _ = safe_url_parts(raw_target)
        host = host_raw or raw_target.lower()
        try:
            http_status = int(record.get("http_status") or 0)
        except (TypeError, ValueError):
            http_status = 0
        plugins = record.get("plugins")
        if not isinstance(plugins, dict):
            continue
        for plugin_name, plugin_data in plugins.items():
            if not isinstance(plugin_name, str) or not plugin_name:
                continue
            if plugin_name in _SKIP_PLUGINS:
                continue
            versions = _extract_versions(plugin_data)
            if not versions:
                versions = [""]
            for version in versions:
                key: _DedupKey = (host, plugin_name, version)
                if key in seen:
                    continue
                seen.add(key)
                confidence = (
                    ConfidenceLevel.CONFIRMED if version else ConfidenceLevel.LIKELY
                )
                finding = _build_finding(confidence)
                evidence: dict[str, object] = {
                    "tool_id": tool_id,
                    "host": host,
                    "http_status": http_status,
                    "plugin": plugin_name,
                    "version": version,
                    "fingerprint_hash": stable_hash_12(
                        f"{host}|{plugin_name}|{version}"
                    ),
                }
                keyed.append((key, finding, _serialise(evidence)))
                if len(keyed) >= _MAX_FINDINGS:
                    _logger.warning(
                        "whatweb.cap_reached",
                        extra={
                            "event": "whatweb_cap_reached",
                            "tool_id": tool_id,
                            "cap": _MAX_FINDINGS,
                        },
                    )
                    break
            if len(keyed) >= _MAX_FINDINGS:
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
                "whatweb.artifact_unreadable",
                extra={
                    "event": "whatweb_artifact_unreadable",
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


def _normalise_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        if "plugins" in payload or "target" in payload:
            return [payload]
    return []


def _extract_versions(plugin_data: Any) -> list[str]:
    """Return ordered, unique version strings from a WhatWeb plugin entry.

    WhatWeb stores per-plugin facts under shape-flexible keys
    (``version`` / ``string`` / ``module`` / ``account``).  We pick
    the ``version`` slot when present (most precise); otherwise
    fall back to ``string`` so generic banners still surface.
    """
    if not isinstance(plugin_data, dict):
        return []
    raw_versions: Iterable[Any] = ()
    for key in ("version", "string", "module"):
        candidate = plugin_data.get(key)
        if isinstance(candidate, list) and candidate:
            raw_versions = candidate
            break
    out: list[str] = []
    for item in raw_versions:
        if isinstance(item, str) and item.strip():
            cleaned = item.strip()
            if cleaned not in out:
                out.append(cleaned)
        elif isinstance(item, (int, float)):
            cleaned = str(item)
            if cleaned not in out:
                out.append(cleaned)
    return out


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
    "parse_whatweb",
]
