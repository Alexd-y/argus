"""Parser for ``syft`` CycloneDX-JSON output (Backlog §4.15 — ARG-029).

Anchore Syft emits a CycloneDX SBOM; we don't treat the SBOM itself as
a vulnerability — Grype/Trivy do that — but we DO surface a single
SUPPLY_CHAIN INFO finding that pins the analysed image and component
count, plus per-component INFO findings whose evidence preserves the
PURL and licence so downstream correlation tools can reach them
without re-parsing the raw artefact.

Canonical envelope (CycloneDX 1.5 / 1.6):

.. code-block:: json

    {
      "bomFormat":   "CycloneDX",
      "specVersion": "1.5",
      "metadata": {
        "component": {"name": "registry/example/api", "type": "container"}
      },
      "components": [
        {
          "type":     "library",
          "name":     "openssl",
          "version":  "3.0.7-r0",
          "purl":     "pkg:apk/alpine/openssl@3.0.7-r0?...",
          "licenses": [{"license": {"id": "Apache-2.0"}}]
        }
      ]
    }

Translation rules
-----------------

* **Inventory finding** (always emitted when ``components`` is
  non-empty) — captures image identifier and component count, severity
  ``info``, CWE-1395 (insecure dependency hint).
* **Per-component findings** — one INFO finding per ``library`` /
  ``application`` / ``framework`` component, deduped on
  ``(name, version, purl)``.  Capped at ``_MAX_COMPONENT_FINDINGS``
  to keep the dispatch contract bounded for fat images.
* **Confidence** is :class:`ConfidenceLevel.CONFIRMED` (Syft pulled
  these from layer manifests).

Sidecar lives at ``artifacts_dir / "syft_findings.jsonl"``.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "syft_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "sbom.json"
_MAX_COMPONENT_FINDINGS: Final[int] = 5_000
_RELEVANT_TYPES: Final[frozenset[str]] = frozenset(
    {"library", "framework", "application", "operating-system"}
)


DedupKey: TypeAlias = tuple[str, str, str]


def parse_syft_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate a Syft CycloneDX SBOM into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, dict):
        if payload is not None:
            _logger.warning(
                "syft_parser.envelope_not_object",
                extra={
                    "event": "syft_parser_envelope_not_object",
                    "tool_id": tool_id,
                    "actual_type": type(payload).__name__,
                },
            )
        return []
    image = _extract_image(payload)
    components = list(_iter_components(payload))
    if not components and image is None:
        return []
    records = list(_build_records(image=image, components=components))
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[int, str, str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            str(record.get("kind") or ""),
            str(record.get("name") or ""),
            str(record.get("version") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            0 if record.get("kind") == "inventory" else 1,
            str(record.get("name") or ""),
            str(record.get("version") or ""),
            str(record.get("purl") or ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_COMPONENT_FINDINGS + 1:
            _logger.warning(
                "syft_parser.cap_reached",
                extra={
                    "event": "syft_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_COMPONENT_FINDINGS,
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


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.SUPPLY_CHAIN,
        cwe=[1395],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "name": record.get("name"),
        "version": record.get("version"),
        "type": record.get("type"),
        "purl": record.get("purl"),
        "licenses": record.get("licenses"),
        "image": record.get("image"),
        "spec_version": record.get("spec_version"),
        "component_count": record.get("component_count"),
    }
    cleaned: dict[str, Any] = {
        key: value
        for key, value in payload.items()
        if value is not None and value != "" and value != []
    }
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _build_records(
    *, image: str | None, components: list[dict[str, Any]]
) -> Iterable[dict[str, Any]]:
    yield {
        "kind": "inventory",
        "name": image or "<unknown image>",
        "version": "",
        "type": "container",
        "purl": None,
        "licenses": None,
        "image": image,
        "component_count": len(components),
    }
    for component in components[:_MAX_COMPONENT_FINDINGS]:
        yield component


def _iter_components(payload: dict[str, Any]) -> Iterator[dict[str, Any]]:
    spec_version = _string_field(payload, "specVersion")
    components = payload.get("components")
    if not isinstance(components, list):
        return
    for component in components:
        if not isinstance(component, dict):
            continue
        component_type = (_string_field(component, "type") or "library").lower()
        if component_type not in _RELEVANT_TYPES:
            continue
        name = _string_field(component, "name")
        if name is None:
            continue
        version = _string_field(component, "version") or ""
        purl = _string_field(component, "purl")
        licenses = _extract_licenses(component)
        yield {
            "kind": "component",
            "name": name,
            "version": version,
            "type": component_type,
            "purl": purl,
            "licenses": licenses,
            "spec_version": spec_version,
        }


def _extract_licenses(component: dict[str, Any]) -> list[str]:
    licenses_field = component.get("licenses")
    if not isinstance(licenses_field, list):
        return []
    extracted: list[str] = []
    for licence in licenses_field:
        if not isinstance(licence, dict):
            continue
        nested = licence.get("license")
        if isinstance(nested, dict):
            value = _string_field(nested, "id") or _string_field(nested, "name")
            if value is not None:
                extracted.append(value)
                continue
        expression = _string_field(licence, "expression")
        if expression is not None:
            extracted.append(expression)
    return sorted(set(extracted))


def _extract_image(payload: dict[str, Any]) -> str | None:
    metadata = payload.get("metadata")
    if isinstance(metadata, dict):
        component = metadata.get("component")
        if isinstance(component, dict):
            name = _string_field(component, "name")
            version = _string_field(component, "version")
            if name is not None and version is not None:
                return f"{name}@{version}"
            if name is not None:
                return name
    source = payload.get("source")
    if isinstance(source, dict):
        target = source.get("target")
        if isinstance(target, dict):
            return _string_field(target, "userInput") or _string_field(
                target, "imageID"
            )
        if isinstance(target, str):
            stripped = target.strip()
            return stripped or None
    return None


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_syft_json",
]
