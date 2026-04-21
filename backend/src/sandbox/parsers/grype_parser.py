"""Parser for Anchore Grype ``-o json`` output (Backlog/dev1_md §4.15 — ARG-021).

Anchore Grype matches container/SBOM packages against its vulnerability
DB (NVD + distro advisories + GHSA). Output:

.. code-block:: json

    {
      "matches": [
        {
          "vulnerability": {
            "id":          "CVE-2024-12345",
            "dataSource":  "https://nvd.nist.gov/vuln/detail/CVE-2024-12345",
            "namespace":   "nvd:cpe",
            "severity":    "High",
            "urls":        ["https://..."],
            "description": "...",
            "cvss": [
              {
                "version": "3.1",
                "vector":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "metrics": {"baseScore": 9.8, "exploitabilityScore": 3.9, "impactScore": 5.9}
              }
            ],
            "fix":         {"versions": ["1.2.4"], "state": "fixed"}
          },
          "relatedVulnerabilities": [
            {
              "id":   "GHSA-...",
              "cwes": ["CWE-22", "CWE-79"]
            }
          ],
          "matchDetails": [
            {
              "type":     "exact-direct-match",
              "matcher":  "rpm-matcher",
              "searchedBy": {...},
              "found":      {"versionConstraint": "< 1.2.4 (rpm)"}
            }
          ],
          "artifact": {
            "name":      "openssl",
            "version":   "1.2.3-1.el9",
            "type":      "rpm",
            "purl":      "pkg:rpm/redhat/openssl@1.2.3-1.el9",
            "locations": [{"path": "/var/lib/rpm/Packages"}]
          }
        }
      ],
      "source":         {"target": "...", "type": "image"},
      "distro":         {"name": "rhel", "version": "9.2"},
      "descriptor":     {"name": "grype", "version": "0.74.0"}
    }

Translation rules
-----------------

* **Severity** — Grype emits ``Critical`` / ``High`` / ``Medium`` /
  ``Low`` / ``Negligible`` / ``Unknown``. Mapped one-to-one (``Negligible``
  → ``info``, ``Unknown`` → ``info``).

* **Confidence** — :class:`ConfidenceLevel.CONFIRMED` for any
  vulnerability with a CPE/PURL match (Grype only emits matches where
  the package version satisfies the advisory's vulnerable range), so
  presence is essentially deterministic. Reachability is a separate
  concern handled by the Normaliser.

* **Category** — :class:`FindingCategory.SUPPLY_CHAIN` (Grype is a
  package-based SCA scanner; every match is a CVE on a dependency).

* **CWE** — sourced from ``relatedVulnerabilities[].cwes[]`` (each
  ``"CWE-22"`` token); falls back to ``[1395]`` (Dependency on Vulnerable
  Third-Party Component, MITRE 2024).

* **CVSS** — preferred order: Grype's ``cvss[]`` block (highest
  v3.x score wins). Vector is preserved if it starts with ``CVSS:3.``
  or ``CVSS:4.``; otherwise the parser falls back to the per-severity
  sentinel score with :data:`SENTINEL_CVSS_VECTOR`.

Dedup
-----

Stable key: ``(cve_id, package_name, package_version)``. The same CVE
on two distinct packages (e.g., ``glibc`` + ``zlib``) is two findings;
re-runs collapse cleanly.

Sidecar
-------

``artifacts_dir / "grype_findings.jsonl"``.
"""

from __future__ import annotations

import json
import logging
import re
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
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "grype_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "grype.json"
_MAX_FINDINGS: Final[int] = 10_000
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


_CWE_SUPPLY_CHAIN_DEFAULT: Final[tuple[int, ...]] = (1395,)
_OWASP_WSTG_DEFAULT: Final[tuple[str, ...]] = ("WSTG-CONF-04", "WSTG-INFO-08")


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 0.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


_CVSS_VECTOR_RE: Final[re.Pattern[str]] = re.compile(r"^CVSS:[34](?:\.\d+)?/")
_CVE_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"\bCVE-\d{4}-\d{4,7}\b")


DedupKey: TypeAlias = tuple[str, str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_grype_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Grype ``-o json`` output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if payload is None:
        return []
    if not isinstance(payload, dict):
        _logger.warning(
            "grype_parser.envelope_not_dict",
            extra={
                "event": "grype_parser_envelope_not_dict",
                "tool_id": tool_id,
            },
        )
        return []
    raw_matches = payload.get("matches")
    if not isinstance(raw_matches, list):
        return []
    records = list(_iter_normalised(raw_matches, tool_id=tool_id))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[DedupKey] = set()
    keyed: list[tuple[tuple[int, str, str, str], DedupKey, FindingDTO, str]] = []
    for record in records:
        key = _dedup_key(record)
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = _sort_key(record)
        keyed.append((sort_key, key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "grype_parser.cap_reached",
                extra={
                    "event": "grype_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break
    keyed.sort(key=lambda item: item[0])
    if keyed:
        _persist_evidence_sidecar(
            artifacts_dir,
            tool_id=tool_id,
            evidence_records=[blob for _, _, _, blob in keyed],
        )
    return [finding for _, _, finding, _ in keyed]


def _dedup_key(record: dict[str, Any]) -> DedupKey:
    return (
        str(record.get("cve_id") or ""),
        str(record.get("package_name") or ""),
        str(record.get("package_version") or ""),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, str]:
    severity = str(record.get("severity") or "info")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("cve_id") or ""),
        str(record.get("package_name") or ""),
        str(record.get("package_version") or ""),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    cwe_list = list(record.get("cwe") or ())
    if not cwe_list:
        cwe_list = list(_CWE_SUPPLY_CHAIN_DEFAULT)
    cvss_vector = str(record.get("cvss_v3_vector") or SENTINEL_CVSS_VECTOR)
    cvss_score = float(record.get("cvss_v3_score") or 0.0)
    return make_finding_dto(
        category=FindingCategory.SUPPLY_CHAIN,
        cwe=cwe_list,
        cvss_v3_vector=cvss_vector,
        cvss_v3_score=cvss_score,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=list(_OWASP_WSTG_DEFAULT),
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "grype",
        "cve_id": record.get("cve_id"),
        "package_name": record.get("package_name"),
        "package_version": record.get("package_version"),
        "package_type": record.get("package_type"),
        "purl": record.get("purl"),
        "namespace": record.get("namespace"),
        "data_source": record.get("data_source"),
        "fix_state": record.get("fix_state"),
        "fix_versions": list(record.get("fix_versions") or ()),
        "match_type": record.get("match_type"),
        "matcher": record.get("matcher"),
        "severity": record.get("severity"),
        "grype_severity": record.get("grype_severity"),
        "cwe": list(record.get("cwe") or ()),
        "cvss_vector": record.get("cvss_v3_vector"),
        "cvss_score": record.get("cvss_v3_score"),
        "description": _truncate_text(record.get("description")),
        "locations": list(record.get("locations") or ()),
        "related_vulnerabilities": list(record.get("related_vulnerabilities") or ()),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None:
            continue
        if isinstance(value, list | tuple) and not value:
            continue
        if value == "":
            continue
        cleaned[key] = value
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _persist_evidence_sidecar(
    artifacts_dir: Path,
    *,
    tool_id: str,
    evidence_records: list[str],
) -> None:
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        sidecar_path = artifacts_dir / EVIDENCE_SIDECAR_NAME
        with sidecar_path.open("w", encoding="utf-8") as fh:
            for blob in evidence_records:
                fh.write(blob)
                fh.write("\n")
    except OSError as exc:
        _logger.warning(
            "grype_parser.evidence_sidecar_write_failed",
            extra={
                "event": "grype_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


# ---------------------------------------------------------------------------
# Payload resolution
# ---------------------------------------------------------------------------


def _load_payload(*, stdout: bytes, artifacts_dir: Path, tool_id: str) -> Any:
    canonical = _safe_join(artifacts_dir, _CANONICAL_FILENAME)
    if canonical is not None and canonical.is_file():
        try:
            raw = canonical.read_bytes()
        except OSError as exc:
            _logger.warning(
                "grype_parser.canonical_read_failed",
                extra={
                    "event": "grype_parser_canonical_read_failed",
                    "tool_id": tool_id,
                    "path": _CANONICAL_FILENAME,
                    "error_type": type(exc).__name__,
                },
            )
            raw = b""
        if raw.strip():
            payload = safe_load_json(raw, tool_id=tool_id)
            if payload is not None:
                return payload
    if stdout and stdout.strip():
        return safe_load_json(stdout, tool_id=tool_id)
    return None


def _safe_join(base: Path, name: str) -> Path | None:
    if "/" in name or "\\" in name or ".." in name:
        return None
    return base / name


# ---------------------------------------------------------------------------
# Record normalisation
# ---------------------------------------------------------------------------


def _iter_normalised(
    raw_matches: list[Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    for raw in raw_matches:
        if not isinstance(raw, dict):
            continue
        vuln = raw.get("vulnerability")
        artifact = raw.get("artifact")
        if not isinstance(vuln, dict) or not isinstance(artifact, dict):
            _logger.warning(
                "grype_parser.match_missing_field",
                extra={
                    "event": "grype_parser_match_missing_field",
                    "tool_id": tool_id,
                },
            )
            continue
        cve_id = _normalise_cve_id(_string_field(vuln, "id"))
        if cve_id is None:
            _logger.warning(
                "grype_parser.match_missing_cve",
                extra={
                    "event": "grype_parser_match_missing_cve",
                    "tool_id": tool_id,
                },
            )
            continue
        package_name = _string_field(artifact, "name")
        package_version = _string_field(artifact, "version") or ""
        if package_name is None:
            _logger.warning(
                "grype_parser.artifact_missing_name",
                extra={
                    "event": "grype_parser_artifact_missing_name",
                    "tool_id": tool_id,
                },
            )
            continue
        grype_severity = _string_field(vuln, "severity") or "Unknown"
        severity = _map_severity(grype_severity)
        cvss_vector, cvss_score = _extract_cvss(
            vuln.get("cvss"), severity_fallback=severity
        )
        related = _extract_related(raw.get("relatedVulnerabilities"))
        cwe_list = _collect_cwes(vuln, related)
        fix_versions, fix_state = _extract_fix(vuln.get("fix"))
        match_type, matcher = _extract_match_details(raw.get("matchDetails"))
        urls_block = vuln.get("urls")
        urls = list(urls_block) if isinstance(urls_block, list) else []
        related_ids = sorted(
            {
                related_id
                for related_id in (_string_field(item, "id") for item in related)
                if related_id is not None
            }
        )
        yield {
            "cve_id": cve_id,
            "package_name": package_name,
            "package_version": package_version,
            "package_type": _string_field(artifact, "type"),
            "purl": _string_field(artifact, "purl"),
            "namespace": _string_field(vuln, "namespace"),
            "data_source": _string_field(vuln, "dataSource"),
            "fix_state": fix_state,
            "fix_versions": fix_versions,
            "match_type": match_type,
            "matcher": matcher,
            "severity": severity,
            "grype_severity": grype_severity,
            "cwe": cwe_list,
            "cvss_v3_vector": cvss_vector,
            "cvss_v3_score": cvss_score,
            "description": _string_field(vuln, "description"),
            "urls": urls,
            "locations": _extract_locations(artifact.get("locations")),
            "related_vulnerabilities": related_ids,
        }


def _map_severity(raw: str) -> str:
    lowered = raw.strip().lower()
    if lowered in {"critical", "high", "medium", "low"}:
        return lowered
    if lowered in {"negligible", "unknown", ""}:
        return "info"
    return "info"


def _normalise_cve_id(raw: str | None) -> str | None:
    if raw is None:
        return None
    token = raw.strip()
    if not token:
        return None
    if _CVE_TOKEN_RE.fullmatch(token):
        return token
    if token.startswith("GHSA-") and len(token) >= 12:
        return token
    if token.upper().startswith("CVE-") and len(token) >= 9:
        return token.upper()
    return token


def _extract_cvss(raw: Any, *, severity_fallback: str) -> tuple[str, float]:
    if not isinstance(raw, list):
        return SENTINEL_CVSS_VECTOR, _SEVERITY_TO_CVSS.get(severity_fallback, 0.0)
    best_score = -1.0
    best_vector = SENTINEL_CVSS_VECTOR
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        vector = _string_field(entry, "vector") or ""
        if not _CVSS_VECTOR_RE.match(vector):
            continue
        metrics = entry.get("metrics")
        score = (
            _coerce_float(metrics.get("baseScore"))
            if isinstance(metrics, dict)
            else None
        )
        if score is None:
            continue
        if score > best_score:
            best_score = score
            best_vector = vector
    if best_score < 0:
        return SENTINEL_CVSS_VECTOR, _SEVERITY_TO_CVSS.get(severity_fallback, 0.0)
    return best_vector, best_score


def _extract_related(raw: Any) -> list[dict[str, Any]]:
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, dict)]


def _collect_cwes(vuln: dict[str, Any], related: list[dict[str, Any]]) -> list[int]:
    out: set[int] = set()
    for source in [vuln, *related]:
        for value in _extract_cwe(source.get("cwes")):
            out.add(value)
        for value in _extract_cwe(source.get("cwe")):
            out.add(value)
    return sorted(out)


def _extract_cwe(raw: Any) -> list[int]:
    if isinstance(raw, list):
        out: list[int] = []
        for item in raw:
            for value in _extract_cwe(item):
                out.append(value)
        return out
    if isinstance(raw, bool):
        return []
    if isinstance(raw, int) and raw > 0:
        return [raw]
    if isinstance(raw, str):
        token = raw.strip().upper()
        if token.startswith("CWE-"):
            token = token[4:]
        if token.isdigit():
            value = int(token)
            return [value] if value > 0 else []
    if isinstance(raw, dict):
        return _extract_cwe(raw.get("id") or raw.get("cwe"))
    return []


def _extract_fix(raw: Any) -> tuple[list[str], str | None]:
    if not isinstance(raw, dict):
        return [], None
    versions_raw = raw.get("versions")
    versions: list[str] = []
    if isinstance(versions_raw, list):
        for item in versions_raw:
            if isinstance(item, str) and item.strip():
                versions.append(item.strip())
    state = raw.get("state")
    state_str = state.strip() if isinstance(state, str) and state.strip() else None
    return versions, state_str


def _extract_match_details(
    raw: Any,
) -> tuple[str | None, str | None]:
    if not isinstance(raw, list) or not raw:
        return None, None
    first = raw[0]
    if not isinstance(first, dict):
        return None, None
    return _string_field(first, "type"), _string_field(first, "matcher")


def _extract_locations(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, dict):
            path = _string_field(item, "path")
            if path is not None:
                out.append(path)
        elif isinstance(item, str) and item.strip():
            out.append(item.strip())
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _coerce_float(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def _truncate_text(text: str | None) -> str | None:
    if text is None or text == "":
        return None
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_BYTES:
        return text
    truncated = encoded[:_MAX_EVIDENCE_BYTES].decode("utf-8", errors="replace")
    return truncated + "...[truncated]"


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_grype_json",
]
