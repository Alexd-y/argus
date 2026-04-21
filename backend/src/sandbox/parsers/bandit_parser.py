"""Parser for Bandit ``-f json`` output (Backlog/dev1_md §4.16 — ARG-021).

PyCQA Bandit is the canonical Python SAST scanner; the wrapper is invoked
as ``bandit -r {path} -f json -o /out/bandit.json -q``. Bandit always
writes a single JSON envelope with the following shape (Bandit 1.7+):

.. code-block:: json

    {
      "errors": [],
      "generated_at": "2026-04-19T12:00:00Z",
      "metrics": {"_totals": {"loc": 1234, ...}, "src/foo.py": {...}},
      "results": [
        {
          "code":              "  41 import subprocess\\n  42 subprocess.run(...)",
          "col_offset":         9,
          "filename":           "src/foo.py",
          "issue_confidence":   "HIGH",
          "issue_cwe":          {"id": 78, "link": "https://cwe.mitre.org/..."},
          "issue_severity":     "HIGH",
          "issue_text":         "subprocess call with shell=True identified",
          "line_number":        42,
          "line_range":         [42, 44],
          "more_info":          "https://bandit.readthedocs.io/...",
          "test_id":            "B602",
          "test_name":          "subprocess_popen_with_shell_equals_true"
        }
      ]
    }

Translation rules
-----------------

* **Severity** — Bandit emits ``HIGH`` / ``MEDIUM`` / ``LOW`` (uppercase).
  Mapped one-to-one onto ARGUS buckets (``LOW`` → ``low``); unknown
  severities collapse to ``info``.

* **Confidence** — Bandit's ``issue_confidence`` codifies the
  precision of the rule, exactly mirroring our ``ConfidenceLevel``
  ladder:

  - ``HIGH``   → :class:`ConfidenceLevel.CONFIRMED` (deterministic AST match).
  - ``MEDIUM`` → :class:`ConfidenceLevel.LIKELY`.
  - ``LOW``    → :class:`ConfidenceLevel.SUSPECTED` (heuristic).

* **Category** — Bandit rules cover both security smells (``B6xx`` —
  injection family) and best-practice / hardening (``B1xx`` — assert
  statement). Without a richer taxonomy on disk, we route every result
  through CWE → :class:`FindingCategory` (sqli / xss / rce / crypto /
  …) and fall back to :class:`FindingCategory.MISCONFIG` for findings
  whose CWE does not unambiguously place them in a OWASP / WSTG
  bucket.

* **CWE** — pulled from ``issue_cwe.id`` (Bandit ships the canonical
  MITRE CWE id per rule). Defaults to per-category fallback when the
  rule omits it.

* **CVSS** — Bandit does not surface a CVSS vector / score (it is a
  rule-based SAST tool, not a CVE database). We anchor a per-severity
  sentinel score (matches the Semgrep pattern) so the prioritiser can
  rank ``HIGH`` over ``LOW`` without waiting for the Normaliser.

Dedup
-----

Stable key: ``(test_id, filename, line_number)``. Two distinct rules
matching the same line are two findings; the same rule re-matching
the exact same span is one.

Cap
---

Hard-limited to :data:`_MAX_FINDINGS = 5_000` so a Bandit run over a
mono-repo with thousands of low-severity B101 (assert) hits cannot
exhaust worker memory.

Sidecar
-------

Every emitted record is mirrored into
``artifacts_dir / "bandit_findings.jsonl"``.
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
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "bandit_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "bandit.json"
_MAX_FINDINGS: Final[int] = 5_000
_MAX_EVIDENCE_BYTES: Final[int] = 4 * 1024


# Per-severity CVSS anchor (Bandit emits no CVSS vector). Mirrors the
# Semgrep parser's anchoring on Backlog/dev1_md §11 priority weights.
_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "high": 7.0,
    "medium": 5.0,
    "low": 3.5,
    "info": 0.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


# Bandit confidence → ARGUS confidence ladder.
_CONFIDENCE_MAP: Final[dict[str, ConfidenceLevel]] = {
    "HIGH": ConfidenceLevel.CONFIRMED,
    "MEDIUM": ConfidenceLevel.LIKELY,
    "LOW": ConfidenceLevel.SUSPECTED,
}


# CWE → FindingCategory routing — Bandit's rule set covers an exhaustive
# slice of the CWE Top-25 + common Python gotchas. Anything not listed
# here falls back to MISCONFIG (reasonable default for an SAST hit
# without a clear OWASP bucket).
_CWE_TO_CATEGORY: Final[dict[int, FindingCategory]] = {
    22: FindingCategory.LFI,
    73: FindingCategory.LFI,
    78: FindingCategory.RCE,
    79: FindingCategory.XSS,
    89: FindingCategory.SQLI,
    94: FindingCategory.RCE,
    95: FindingCategory.RCE,
    98: FindingCategory.LFI,
    113: FindingCategory.MISCONFIG,
    200: FindingCategory.INFO,
    250: FindingCategory.MISCONFIG,
    259: FindingCategory.SECRET_LEAK,
    295: FindingCategory.CRYPTO,
    297: FindingCategory.CRYPTO,
    310: FindingCategory.CRYPTO,
    311: FindingCategory.CRYPTO,
    326: FindingCategory.CRYPTO,
    327: FindingCategory.CRYPTO,
    330: FindingCategory.CRYPTO,
    345: FindingCategory.JWT,
    400: FindingCategory.DOS,
    502: FindingCategory.RCE,
    601: FindingCategory.OPEN_REDIRECT,
    611: FindingCategory.XXE,
    693: FindingCategory.MISCONFIG,
    703: FindingCategory.INFO,
    732: FindingCategory.MISCONFIG,
    798: FindingCategory.SECRET_LEAK,
    918: FindingCategory.SSRF,
    943: FindingCategory.NOSQLI,
}


_CATEGORY_DEFAULT_CWE: Final[dict[FindingCategory, tuple[int, ...]]] = {
    FindingCategory.RCE: (78, 94),
    FindingCategory.SQLI: (89,),
    FindingCategory.XSS: (79,),
    FindingCategory.SSRF: (918,),
    FindingCategory.LFI: (22,),
    FindingCategory.SECRET_LEAK: (798,),
    FindingCategory.CRYPTO: (327,),
    FindingCategory.XXE: (611,),
    FindingCategory.OPEN_REDIRECT: (601,),
    FindingCategory.NOSQLI: (943,),
    FindingCategory.JWT: (345,),
    FindingCategory.DOS: (400,),
    FindingCategory.MISCONFIG: (16, 1032),
    FindingCategory.INFO: (200,),
}


_OWASP_BY_CATEGORY: Final[dict[FindingCategory, tuple[str, ...]]] = {
    FindingCategory.RCE: ("WSTG-INPV-12",),
    FindingCategory.SQLI: ("WSTG-INPV-05",),
    FindingCategory.XSS: ("WSTG-INPV-01", "WSTG-INPV-02"),
    FindingCategory.SSRF: ("WSTG-INPV-19",),
    FindingCategory.LFI: ("WSTG-ATHZ-01",),
    FindingCategory.SECRET_LEAK: ("WSTG-ATHN-06", "WSTG-INFO-08"),
    FindingCategory.CRYPTO: ("WSTG-CRYP-01",),
    FindingCategory.XXE: ("WSTG-INPV-07",),
    FindingCategory.OPEN_REDIRECT: ("WSTG-CLNT-04",),
    FindingCategory.NOSQLI: ("WSTG-INPV-05",),
    FindingCategory.JWT: ("WSTG-SESS-09",),
    FindingCategory.DOS: ("WSTG-BUSL-01",),
    FindingCategory.MISCONFIG: ("WSTG-CONF-04",),
    FindingCategory.INFO: ("WSTG-INFO-08",),
}


DedupKey: TypeAlias = tuple[str, str, int]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_bandit_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Bandit ``-f json`` output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if payload is None:
        return []
    if not isinstance(payload, dict):
        _logger.warning(
            "bandit_parser.envelope_not_dict",
            extra={
                "event": "bandit_parser_envelope_not_dict",
                "tool_id": tool_id,
            },
        )
        return []
    _surface_scan_errors(payload, tool_id=tool_id)
    raw_results = payload.get("results")
    if not isinstance(raw_results, list):
        return []
    records = list(_iter_normalised(raw_results, tool_id=tool_id))
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
                "bandit_parser.cap_reached",
                extra={
                    "event": "bandit_parser_cap_reached",
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
        str(record.get("test_id") or ""),
        str(record.get("filename") or ""),
        int(record.get("line_number") or 0),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, int]:
    severity = str(record.get("severity") or "info")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("test_id") or ""),
        str(record.get("filename") or ""),
        int(record.get("line_number") or 0),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    category: FindingCategory = record["category"]
    cwe_list = list(record.get("cwe") or ())
    if not cwe_list:
        cwe_list = list(_CATEGORY_DEFAULT_CWE.get(category, (200,)))
    confidence: ConfidenceLevel = record["confidence"]
    cvss_score: float = float(record.get("cvss_v3_score") or 0.0)
    owasp_wstg = list(record.get("owasp_wstg") or ())
    return make_finding_dto(
        category=category,
        cwe=cwe_list,
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=cvss_score,
        confidence=confidence,
        owasp_wstg=owasp_wstg,
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "bandit",
        "test_id": record.get("test_id"),
        "test_name": record.get("test_name"),
        "filename": record.get("filename"),
        "line_number": record.get("line_number"),
        "line_range": list(record.get("line_range") or ()),
        "col_offset": record.get("col_offset"),
        "severity": record.get("severity"),
        "bandit_severity": record.get("bandit_severity"),
        "bandit_confidence": record.get("bandit_confidence"),
        "cwe": list(record.get("cwe") or ()),
        "more_info": record.get("more_info"),
        "issue_text": _truncate_text(record.get("issue_text")),
        "code_snippet": _truncate_text(record.get("code_snippet")),
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
            "bandit_parser.evidence_sidecar_write_failed",
            extra={
                "event": "bandit_parser_evidence_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


def _surface_scan_errors(payload: dict[str, Any], *, tool_id: str) -> None:
    errors = payload.get("errors")
    if not isinstance(errors, list) or not errors:
        return
    _logger.warning(
        "bandit_parser.scan_errors",
        extra={
            "event": "bandit_parser_scan_errors",
            "tool_id": tool_id,
            "error_count": len(errors),
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
                "bandit_parser.canonical_read_failed",
                extra={
                    "event": "bandit_parser_canonical_read_failed",
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
    raw_results: list[Any], *, tool_id: str
) -> Iterable[dict[str, Any]]:
    for raw in raw_results:
        if not isinstance(raw, dict):
            continue
        test_id = _string_field(raw, "test_id")
        filename = _string_field(raw, "filename")
        if test_id is None or filename is None:
            _logger.warning(
                "bandit_parser.result_missing_field",
                extra={
                    "event": "bandit_parser_result_missing_field",
                    "tool_id": tool_id,
                    "missing": "test_id" if test_id is None else "filename",
                },
            )
            continue
        line_number = _coerce_int(raw.get("line_number")) or 0
        line_range = _extract_line_range(raw.get("line_range"))
        col_offset = _coerce_int(raw.get("col_offset"))
        bandit_severity = (_string_field(raw, "issue_severity") or "LOW").upper()
        bandit_confidence = (_string_field(raw, "issue_confidence") or "LOW").upper()
        severity = _map_severity(bandit_severity)
        confidence = _CONFIDENCE_MAP.get(bandit_confidence, ConfidenceLevel.SUSPECTED)
        cwe_list = _extract_cwe(raw.get("issue_cwe"))
        category = _classify_category(cwe_list=cwe_list, test_id=test_id)
        owasp_wstg = _OWASP_BY_CATEGORY.get(category, ("WSTG-INFO-08",))
        cvss_score = _SEVERITY_TO_CVSS.get(severity, 0.0)
        yield {
            "test_id": test_id,
            "test_name": _string_field(raw, "test_name"),
            "filename": filename,
            "line_number": line_number,
            "line_range": line_range,
            "col_offset": col_offset,
            "severity": severity,
            "bandit_severity": bandit_severity,
            "bandit_confidence": bandit_confidence,
            "category": category,
            "confidence": confidence,
            "cwe": cwe_list,
            "owasp_wstg": owasp_wstg,
            "cvss_v3_score": cvss_score,
            "more_info": _string_field(raw, "more_info"),
            "issue_text": _string_field(raw, "issue_text"),
            "code_snippet": _string_field(raw, "code"),
        }


def _map_severity(raw: str) -> str:
    lowered = raw.strip().lower()
    if lowered in {"high", "medium", "low"}:
        return lowered
    return "info"


def _classify_category(*, cwe_list: list[int], test_id: str) -> FindingCategory:
    for cwe_id in cwe_list:
        bucket = _CWE_TO_CATEGORY.get(cwe_id)
        if bucket is not None:
            return bucket
    # Bandit test_ids encode rule families: B1xx assert / hardening,
    # B2xx try-except, B3xx blacklist (md5/random/etc), B4xx imports,
    # B5xx crypto, B6xx injection, B7xx XSS-Jinja. Use the first-digit
    # prefix as a coarse fallback.
    if test_id.startswith("B6"):
        return FindingCategory.RCE
    if test_id.startswith("B5") or test_id.startswith("B3"):
        return FindingCategory.CRYPTO
    if test_id.startswith("B7"):
        return FindingCategory.XSS
    return FindingCategory.MISCONFIG


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
    if isinstance(value, str) and value.strip().isdigit():
        candidate = int(value.strip())
        return candidate if candidate >= 0 else None
    return None


def _extract_cwe(raw: Any) -> list[int]:
    if isinstance(raw, dict):
        cwe_id = _coerce_int(raw.get("id"))
        return [cwe_id] if cwe_id is not None and cwe_id > 0 else []
    if isinstance(raw, list):
        out: list[int] = []
        for item in raw:
            cwe_id = _coerce_int(item)
            if cwe_id is not None and cwe_id > 0:
                out.append(cwe_id)
        return sorted(set(out))
    cwe_id = _coerce_int(raw)
    return [cwe_id] if cwe_id is not None and cwe_id > 0 else []


def _extract_line_range(raw: Any) -> list[int]:
    if not isinstance(raw, list):
        return []
    out: list[int] = []
    for item in raw:
        coerced = _coerce_int(item)
        if coerced is not None:
            out.append(coerced)
    return out


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
    "parse_bandit_json",
]
