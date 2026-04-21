"""Parser for ``wappalyzer`` CLI JSON output (Backlog §4.4 — ARG-029).

The Wappalyzer CLI emits a JSON envelope describing detected
technologies for one or more URLs.  Two upstream shapes are common:

1. ``{"urls": {"<url>": {"status": 200, ...}},
    "technologies": [{"name": "Nginx", "categories": [...], ...}]}``
   (modern wrapper; one JSON object per scan invocation)
2. ``[{"url": "...", "technologies": [...]}, ...]``  (older format)

For every detected technology we emit one INFO finding tagged
:class:`FindingCategory.INFO` (CWE-200 — information exposure of
internal stack).  Severity is ``info``; CVSS = 0.0; confidence is
:class:`ConfidenceLevel.LIKELY` because Wappalyzer relies on
heuristics (fingerprints, response headers, JS hashes).

Per-tech evidence captures the version (when present), the categories
(``CDN``, ``Web servers``, ``Programming languages`` etc.) and the
target URL, so downstream nuclei templates and CVE feeds can prioritise
checks.  Highly versioned techs (``vendor / x.y.z``) form their own
dedup key — we don't want to collapse ``nginx 1.18.0`` and
``nginx 1.24.0`` into a single signal.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable, Iterator
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
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "wappalyzer_cli_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "wappalyzer.json"
_MAX_FINDINGS: Final[int] = 5_000


DedupKey: TypeAlias = tuple[str, str, str]


def parse_wappalyzer_cli_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate wappalyzer CLI JSON into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if payload is None:
        return []
    records = list(_iter_records(payload, tool_id=tool_id))
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
    keyed: list[tuple[tuple[str, str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            str(record.get("url") or ""),
            str(record.get("name") or ""),
            str(record.get("version") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding()
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            str(record.get("url") or ""),
            str(record.get("name") or ""),
            str(record.get("version") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "wappalyzer_cli_parser.cap_reached",
                extra={
                    "event": "wappalyzer_cli_parser_cap_reached",
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
        cwe=[200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.LIKELY,
        owasp_wstg=["WSTG-INFO-02", "WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "url": record.get("url"),
        "name": record.get("name"),
        "version": record.get("version"),
        "categories": record.get("categories"),
        "confidence": record.get("confidence"),
        "slug": record.get("slug"),
    }
    cleaned: dict[str, Any] = {
        key: value
        for key, value in payload.items()
        if value is not None and value != "" and value != []
    }
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _iter_records(payload: Any, *, tool_id: str) -> Iterable[dict[str, Any]]:
    if isinstance(payload, dict):
        if "technologies" in payload:
            url = _extract_envelope_url(payload)
            yield from _iter_techs(payload.get("technologies"), url=url)
            return
        if "urls" in payload and isinstance(payload.get("urls"), dict):
            for url, details in payload["urls"].items():
                if not isinstance(details, dict):
                    continue
                yield from _iter_techs(details.get("technologies"), url=str(url))
            return
    if isinstance(payload, list):
        for index, entry in enumerate(payload):
            if not isinstance(entry, dict):
                _logger.debug(
                    "wappalyzer_cli_parser.entry_not_object",
                    extra={
                        "event": "wappalyzer_cli_parser_entry_not_object",
                        "tool_id": tool_id,
                        "index": index,
                    },
                )
                continue
            yield from _iter_techs(
                entry.get("technologies"),
                url=_string_field(entry, "url") or _string_field(entry, "target"),
            )
        return
    _logger.warning(
        "wappalyzer_cli_parser.unsupported_payload",
        extra={
            "event": "wappalyzer_cli_parser_unsupported_payload",
            "tool_id": tool_id,
            "actual_type": type(payload).__name__,
        },
    )


def _extract_envelope_url(payload: dict[str, Any]) -> str | None:
    urls = payload.get("urls")
    if isinstance(urls, dict) and urls:
        return next(iter(urls), None)
    if isinstance(urls, list) and urls:
        first = urls[0]
        return first if isinstance(first, str) else None
    return _string_field(payload, "url")


def _iter_techs(techs: Any, *, url: str | None) -> Iterable[dict[str, Any]]:
    if not isinstance(techs, list):
        return
    for tech in techs:
        if not isinstance(tech, dict):
            continue
        name = _string_field(tech, "name")
        if name is None:
            continue
        version = _string_field(tech, "version") or ""
        categories = _extract_categories(tech.get("categories"))
        yield {
            "url": url,
            "name": name,
            "version": version,
            "categories": categories,
            "confidence": _extract_confidence(tech.get("confidence")),
            "slug": _string_field(tech, "slug"),
        }


def _extract_categories(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    extracted: list[str] = []
    for item in value:
        if isinstance(item, str) and item.strip():
            extracted.append(item.strip())
        elif isinstance(item, dict):
            label = _string_field(item, "name") or _string_field(item, "slug")
            if label is not None:
                extracted.append(label)
    return sorted(set(extracted))


def _extract_confidence(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_wappalyzer_cli_json",
]


def _typecheck_iterator() -> None:  # pragma: no cover - mypy seam
    _: Iterator[dict[str, Any]] = iter([])
    del _
