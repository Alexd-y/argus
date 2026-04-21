"""Parser for MobSF (Mobile Security Framework) API output (Backlog/dev1_md §4.18 — ARG-021).

The MoBSF CLI / REST API emits a deeply nested JSON report whose shape
varies between MobSF versions, scan types (Android APK / iOS IPA /
Windows APPX), and analysis modes. The parser walks every documented
sink defensively:

.. code-block:: text

    payload (root dict, may contain any subset of):
      ├─ code_analysis | findings        # SAST results
      ├─ permissions                     # Android permission audit
      ├─ android_api                     # API misuse
      ├─ binary_analysis                 # native binary checks (NX, PIE, …)
      ├─ manifest_analysis               # AndroidManifest / Info.plist issues
      ├─ secrets                         # extracted secrets (REDACT!)
      ├─ certificate_analysis            # signing certificate issues
      ├─ network_security                # NSC / ATS pinning
      ├─ urls / emails / trackers        # informational

For each section we extract a list of finding-shaped dicts via heuristic
key probing (``findings`` / ``hash`` / ``issue`` / ``rule_id`` /
``key``) and synthesise a normalised record. Records without a stable
identifier are dropped (with a warning) — partial/ambiguous data is
*not* worth a finding.

Translation rules
-----------------

* **Severity** — MoBSF uses ``high`` / ``warning`` / ``info`` /
  ``good`` / ``hotspot`` (lowercase). Map:

  - ``high`` → ``high``
  - ``warning`` → ``medium``
  - ``info`` / ``hotspot`` → ``info``
  - ``good`` → dropped (audit pass).
  - ``critical`` (older MobSF / custom rules) → ``critical``.

* **Confidence** — :class:`ConfidenceLevel.LIKELY` for HIGH/CRITICAL,
  :class:`ConfidenceLevel.SUSPECTED` otherwise.

* **Category** — :class:`FindingCategory.VULNERABILITY` is *not* in the
  ARGUS enum; we route mobile-security findings to the closest bucket:

  - secrets → :class:`FindingCategory.SECRET_LEAK`
  - manifest / NSC / certificate → :class:`FindingCategory.MISCONFIG`
  - crypto / random / hashing → :class:`FindingCategory.CRYPTO`
  - SQL / SQLI rules → :class:`FindingCategory.SQLI`
  - everything else → :class:`FindingCategory.MISCONFIG`

* **CWE** — pulled from rule metadata when present; falls back to
  ``[200, 250, 1032]`` (informational disclosure / privilege).

Dedup
-----

Stable key: ``(rule_id, file, line)`` — ``rule_id`` falls back to the
section name + finding index when MobSF emits an unkeyed list.

Sidecar
-------

``artifacts_dir / "mobsf_findings.jsonl"``. Secret values are
masked through :func:`redact_secret`.
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
    redact_secret,
    safe_load_json,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "mobsf_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "mobsf.json"
_MAX_FINDINGS: Final[int] = 5_000
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


_CWE_DEFAULT: Final[tuple[int, ...]] = (200, 1032)
_CWE_SECRET_LEAK: Final[tuple[int, ...]] = (798,)
_CWE_CRYPTO: Final[tuple[int, ...]] = (327,)
_CWE_MISCONFIG: Final[tuple[int, ...]] = (16, 1032)
_CWE_SQLI: Final[tuple[int, ...]] = (89,)


_OWASP_DEFAULT: Final[tuple[str, ...]] = ("WSTG-INFO-08",)
_OWASP_SECRET_LEAK: Final[tuple[str, ...]] = ("WSTG-ATHN-06", "WSTG-INFO-08")
_OWASP_CRYPTO: Final[tuple[str, ...]] = ("WSTG-CRYP-01",)
_OWASP_MISCONFIG: Final[tuple[str, ...]] = ("WSTG-CONF-04",)
_OWASP_SQLI: Final[tuple[str, ...]] = ("WSTG-INPV-05",)


_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.0,
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


_DROPPED_LEVELS: Final[frozenset[str]] = frozenset({"good", "secure", "pass"})


# Section name → finding category. Keys are matched as substrings against
# the lower-cased section name MobSF emits (``code_analysis``,
# ``android_secrets``, ``binary_analysis_findings``, …).
_SECTION_CATEGORY: Final[tuple[tuple[str, FindingCategory], ...]] = (
    ("secret", FindingCategory.SECRET_LEAK),
    ("password", FindingCategory.SECRET_LEAK),
    ("api_key", FindingCategory.SECRET_LEAK),
    ("manifest", FindingCategory.MISCONFIG),
    ("network_security", FindingCategory.MISCONFIG),
    ("certificate", FindingCategory.MISCONFIG),
    ("permission", FindingCategory.MISCONFIG),
    ("binary", FindingCategory.MISCONFIG),
    ("crypto", FindingCategory.CRYPTO),
    ("sql", FindingCategory.SQLI),
)


_RULE_KEYWORDS_TO_CATEGORY: Final[tuple[tuple[str, FindingCategory], ...]] = (
    ("secret", FindingCategory.SECRET_LEAK),
    ("hardcoded", FindingCategory.SECRET_LEAK),
    ("password", FindingCategory.SECRET_LEAK),
    ("crypto", FindingCategory.CRYPTO),
    ("md5", FindingCategory.CRYPTO),
    ("sha1", FindingCategory.CRYPTO),
    ("rc4", FindingCategory.CRYPTO),
    ("ecb", FindingCategory.CRYPTO),
    ("sql", FindingCategory.SQLI),
    ("xss", FindingCategory.XSS),
    ("ssl", FindingCategory.MISCONFIG),
    ("tls", FindingCategory.MISCONFIG),
    ("debuggable", FindingCategory.MISCONFIG),
)


_CATEGORY_TO_CWE: Final[dict[FindingCategory, tuple[int, ...]]] = {
    FindingCategory.SECRET_LEAK: _CWE_SECRET_LEAK,
    FindingCategory.CRYPTO: _CWE_CRYPTO,
    FindingCategory.MISCONFIG: _CWE_MISCONFIG,
    FindingCategory.SQLI: _CWE_SQLI,
    FindingCategory.XSS: (79,),
    FindingCategory.INFO: _CWE_DEFAULT,
}


_CATEGORY_TO_OWASP: Final[dict[FindingCategory, tuple[str, ...]]] = {
    FindingCategory.SECRET_LEAK: _OWASP_SECRET_LEAK,
    FindingCategory.CRYPTO: _OWASP_CRYPTO,
    FindingCategory.MISCONFIG: _OWASP_MISCONFIG,
    FindingCategory.SQLI: _OWASP_SQLI,
    FindingCategory.XSS: ("WSTG-INPV-01",),
    FindingCategory.INFO: _OWASP_DEFAULT,
}


# Sections to walk recursively. We restrict the explosion of
# free-form keys MobSF returns; everything outside this set is left
# as informational metadata in the raw report.
_SECTION_KEYS: Final[tuple[str, ...]] = (
    "code_analysis",
    "android_api",
    "binary_analysis",
    "manifest_analysis",
    "secrets",
    "certificate_analysis",
    "network_security",
    "permissions",
    "findings",
    "crypto_analysis",
    "high",
    "warning",
    "info",
)


DedupKey: TypeAlias = tuple[str, str, int]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_mobsf_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate MoBSF API JSON output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if payload is None:
        return []
    if not isinstance(payload, dict):
        _logger.warning(
            "mobsf_parser.envelope_not_dict",
            extra={
                "event": "mobsf_parser_envelope_not_dict",
                "tool_id": tool_id,
            },
        )
        return []
    records = list(_iter_normalised(payload, tool_id=tool_id))
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
    keyed: list[tuple[tuple[int, str, str, int], DedupKey, FindingDTO, str]] = []
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
                "mobsf_parser.cap_reached",
                extra={
                    "event": "mobsf_parser_cap_reached",
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
        str(record.get("rule_id") or ""),
        str(record.get("file") or ""),
        int(record.get("line") or 0),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, int]:
    severity = str(record.get("severity") or "info")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("section") or ""),
        str(record.get("rule_id") or ""),
        int(record.get("line") or 0),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    category: FindingCategory = record["category"]
    cwe_list = list(record.get("cwe") or ())
    if not cwe_list:
        cwe_list = list(_CATEGORY_TO_CWE.get(category, _CWE_DEFAULT))
    owasp = list(_CATEGORY_TO_OWASP.get(category, _OWASP_DEFAULT))
    return make_finding_dto(
        category=category,
        cwe=cwe_list,
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=float(record.get("cvss_v3_score") or 0.0),
        confidence=record["confidence"],
        owasp_wstg=owasp,
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "mobsf",
        "section": record.get("section"),
        "rule_id": record.get("rule_id"),
        "title": _truncate_text(record.get("title")),
        "description": _truncate_text(record.get("description")),
        "file": record.get("file"),
        "line": record.get("line"),
        "severity": record.get("severity"),
        "mobsf_severity": record.get("mobsf_severity"),
        "match_preview": record.get("match_preview"),
        "owasp_mobile": list(record.get("owasp_mobile") or ()),
        "cwe": list(record.get("cwe") or ()),
        "metadata": record.get("metadata"),
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
            "mobsf_parser.evidence_sidecar_write_failed",
            extra={
                "event": "mobsf_parser_evidence_sidecar_write_failed",
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
                "mobsf_parser.canonical_read_failed",
                extra={
                    "event": "mobsf_parser_canonical_read_failed",
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
    payload: dict[str, Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    for section_key in _SECTION_KEYS:
        section = payload.get(section_key)
        if section is None:
            continue
        yield from _walk_section(section, section_key=section_key, tool_id=tool_id)


def _walk_section(
    section: Any,
    *,
    section_key: str,
    tool_id: str,
) -> Iterable[dict[str, Any]]:
    if isinstance(section, dict):
        for rule_key, body in section.items():
            normalised = _normalise_entry(
                body, section_key=section_key, fallback_rule=str(rule_key)
            )
            if normalised is not None:
                yield normalised
            elif isinstance(body, dict):
                # MoBSF nests severity buckets (high/warning/info) inside
                # subsection dicts; recurse one level when no rule data
                # surfaces directly.
                yield from _walk_section(body, section_key=section_key, tool_id=tool_id)
    elif isinstance(section, list):
        for index, item in enumerate(section):
            normalised = _normalise_entry(
                item,
                section_key=section_key,
                fallback_rule=f"{section_key}#{index}",
            )
            if normalised is not None:
                yield normalised


def _normalise_entry(
    body: Any,
    *,
    section_key: str,
    fallback_rule: str,
) -> dict[str, Any] | None:
    if not isinstance(body, dict):
        return None
    severity_raw = (
        _string_field(body, "severity")
        or _string_field(body, "level")
        or _string_field(body, "stat")
    )
    severity_norm = (severity_raw or "").strip().lower()
    if severity_norm in _DROPPED_LEVELS:
        return None
    severity = _map_severity(severity_norm)
    rule_id = (
        _string_field(body, "rule_id")
        or _string_field(body, "id")
        or _string_field(body, "key")
        or fallback_rule
    )
    title = _string_field(body, "title") or _string_field(body, "name")
    description = (
        _string_field(body, "description")
        or _string_field(body, "desc")
        or _string_field(body, "metadata")
    )
    file_path = _string_field(body, "file") or _string_field(body, "file_path")
    files = body.get("files")
    if file_path is None and isinstance(files, list) and files:
        first_file = files[0]
        if isinstance(first_file, str):
            file_path = first_file.strip() or None
        elif isinstance(first_file, dict):
            file_path = _string_field(first_file, "file_path") or _string_field(
                first_file, "name"
            )
    line = _coerce_int(body.get("line")) or _coerce_int(body.get("line_number")) or 0
    cwe_list = _extract_cwe(body.get("cwe") or body.get("cwe_id") or body.get("cweid"))
    owasp_mobile = _extract_str_list(body.get("owasp-mobile") or body.get("masvs"))
    raw_match = (
        _string_field(body, "match")
        or _string_field(body, "value")
        or _string_field(body, "secret")
    )
    needs_redaction = "secret" in section_key.lower() or any(
        kw in (rule_id.lower() if rule_id else "")
        for kw in ("secret", "password", "key")
    )
    match_preview = redact_secret(raw_match) if needs_redaction else raw_match
    category = _classify_category(section_key=section_key, rule_id=rule_id)
    confidence = (
        ConfidenceLevel.LIKELY
        if severity in {"high", "critical"}
        else ConfidenceLevel.SUSPECTED
    )
    metadata = body.get("metadata") if isinstance(body.get("metadata"), str) else None
    return {
        "section": section_key,
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "file": file_path,
        "line": line,
        "severity": severity,
        "mobsf_severity": severity_raw,
        "category": category,
        "confidence": confidence,
        "cwe": cwe_list,
        "owasp_mobile": owasp_mobile,
        "match_preview": match_preview,
        "metadata": _truncate_text(metadata),
        "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
    }


def _map_severity(raw: str) -> str:
    if raw == "high":
        return "high"
    if raw == "critical":
        return "critical"
    if raw == "warning":
        return "medium"
    if raw in {"info", "informational", "hotspot"}:
        return "info"
    if raw == "low":
        return "low"
    if raw == "medium":
        return "medium"
    return "info"


def _classify_category(*, section_key: str, rule_id: str | None) -> FindingCategory:
    section_lower = section_key.lower()
    for token, bucket in _SECTION_CATEGORY:
        if token in section_lower:
            return bucket
    if rule_id is not None:
        rule_lower = rule_id.lower()
        for token, bucket in _RULE_KEYWORDS_TO_CATEGORY:
            if token in rule_lower:
                return bucket
    return FindingCategory.MISCONFIG


def _extract_cwe(raw: Any) -> list[int]:
    if isinstance(raw, dict):
        return _extract_cwe(raw.get("id") or raw.get("cwe"))
    if isinstance(raw, list):
        out: list[int] = []
        for item in raw:
            for value in _extract_cwe(item):
                out.append(value)
        return sorted(set(out))
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
    return []


def _extract_str_list(raw: Any) -> list[str]:
    if isinstance(raw, str) and raw.strip():
        return [raw.strip()]
    if isinstance(raw, list):
        out: list[str] = []
        for item in raw:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
        return out
    return []


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _string_field(record: dict[str, Any], key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int) and value >= 0:
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        candidate = int(value.strip())
        return candidate if candidate >= 0 else None
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
    "parse_mobsf_json",
]
