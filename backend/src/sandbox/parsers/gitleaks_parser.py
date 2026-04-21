"""Parser for Gitleaks ``--report-format json`` output (Backlog/dev1_md §4.16 — ARG-021).

Gitleaks scans git history (or a tree) for committed secrets and emits a
top-level **JSON array** — one object per secret — with the following
shape (Gitleaks 8.x):

.. code-block:: json

    [
      {
        "Description":     "AWS Access Key ID",
        "RuleID":          "aws-access-token",
        "StartLine":       12,
        "EndLine":         12,
        "StartColumn":     17,
        "EndColumn":       57,
        "Match":           "aws_access_key_id = AKIA...EXAMPLE",
        "Secret":          "AKIAIOSFODNN7EXAMPLE",
        "File":            "src/config/dev.env",
        "SymlinkFile":     "",
        "Commit":          "abc123def456...",
        "Entropy":         4.81,
        "Author":          "alice",
        "Email":           "alice@example.com",
        "Date":            "2026-04-19T11:00:00Z",
        "Message":         "wip: local dev creds",
        "Tags":            ["aws", "key"],
        "Fingerprint":     "abc123def456:src/config/dev.env:aws-access-token:12"
      }
    ]

CRITICAL — secret redaction
---------------------------

The wrapper **never** writes raw ``Match`` or ``Secret`` values to disk.
Both fields pass through :func:`src.sandbox.parsers._base.redact_secret`,
keeping a 4-char prefix + 2-char suffix (enough for an analyst to spot
``ghp_`` / ``AKIA`` / ``sk_live_``) and replacing the middle with
``***REDACTED({len})***``.

Translation rules
-----------------

* **Severity** is rule-derived (Gitleaks itself does not surface a
  severity field). Mapping:

  - ``aws-*``, ``gcp-*``, ``azure-*``, ``stripe-live-*``,
    ``private-key`` → ``critical`` (CRITICAL trigger when the rule id
    encodes either ``private`` or ``aws``).
  - Generic API keys (``slack-*``, ``github-*``, ``jwt``,
    ``generic-api-key``) → ``high``.
  - All other rules → ``medium`` (still actionable, lower urgency).

* **Confidence** — Gitleaks runs an entropy + regex match, so any
  finding it emits is treated as :class:`ConfidenceLevel.CONFIRMED` —
  there's no ambiguity over whether the secret is *present*; the only
  open question is whether it has been rotated.

* **Category** — :class:`FindingCategory.SECRET_LEAK` for everything
  this parser yields.

* **CWE** — pinned at ``798`` (Use of Hard-coded Credentials) per
  MITRE.

Dedup
-----

``Fingerprint`` is preferred when present; otherwise the parser
synthesises ``(RuleID, File, StartLine)`` to collapse re-runs over the
same blob.

Cap
---

Hard-limited to :data:`_MAX_FINDINGS = 5_000` so a noisy ``--no-git``
scan over a vendored ``node_modules/`` cannot exhaust worker memory.

Sidecar
-------

Mirrored into ``artifacts_dir / "gitleaks_findings.jsonl"``. The
sidecar contains the redacted preview only — never the raw secret.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "gitleaks_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "gitleaks.json"
_MAX_FINDINGS: Final[int] = 5_000
_MAX_EVIDENCE_BYTES: Final[int] = 2 * 1024


# CWE-798 — Use of Hard-coded Credentials. Single canonical CWE for
# the secret-leak category.
_CWE_HARDCODED_CREDS: Final[int] = 798


# Per-severity CVSS anchor (Gitleaks emits no CVSS). Mirrors the
# Trivy / Semgrep parser pattern.
_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 6.0,
    "low": 3.5,
    "info": 0.0,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


# Rule-id keyword → severity. Order matters (first match wins). Tokens
# match against ``rule_id.lower()`` *and* ``description.lower()`` so a
# generic rule mentioning "aws secret access key" still escalates.
_CRITICAL_KEYWORDS: Final[tuple[str, ...]] = (
    "private",
    "private-key",
    "aws",
    "gcp",
    "azure-storage-account",
    "stripe-live",
    "rsa-private",
    "ssh-private",
    "pgp-private",
)
_HIGH_KEYWORDS: Final[tuple[str, ...]] = (
    "github",
    "gitlab",
    "slack",
    "jwt",
    "generic-api-key",
    "stripe",
    "twilio",
    "sendgrid",
    "shopify",
    "discord",
    "datadog",
    "circleci",
)


DedupKey: TypeAlias = tuple[str, str, int]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_gitleaks_json(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate Gitleaks ``--report-format json`` output into FindingDTOs."""
    del stderr
    payload = _load_payload(stdout=stdout, artifacts_dir=artifacts_dir, tool_id=tool_id)
    if payload is None:
        return []
    if not isinstance(payload, list):
        _logger.warning(
            "gitleaks_parser.envelope_not_list",
            extra={
                "event": "gitleaks_parser_envelope_not_list",
                "tool_id": tool_id,
                "actual_type": type(payload).__name__,
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
                "gitleaks_parser.cap_reached",
                extra={
                    "event": "gitleaks_parser_cap_reached",
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
    fingerprint = record.get("fingerprint")
    if isinstance(fingerprint, str) and fingerprint.strip():
        return (fingerprint.strip(), "", 0)
    return (
        str(record.get("rule_id") or ""),
        str(record.get("file") or ""),
        int(record.get("start_line") or 0),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, int]:
    severity = str(record.get("severity") or "info")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("rule_id") or ""),
        str(record.get("file") or ""),
        int(record.get("start_line") or 0),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.SECRET_LEAK,
        cwe=[_CWE_HARDCODED_CREDS],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=float(record.get("cvss_v3_score") or 0.0),
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-ATHN-06", "WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "gitleaks",
        "rule_id": record.get("rule_id"),
        "description": record.get("description"),
        "file": record.get("file"),
        "start_line": record.get("start_line"),
        "end_line": record.get("end_line"),
        "start_column": record.get("start_column"),
        "end_column": record.get("end_column"),
        "commit": record.get("commit"),
        "author": record.get("author"),
        "email": record.get("email"),
        "date": record.get("date"),
        "entropy": record.get("entropy"),
        "tags": list(record.get("tags") or ()),
        "severity": record.get("severity"),
        "match_preview": record.get("match_preview"),
        "secret_preview": record.get("secret_preview"),
        "fingerprint": record.get("fingerprint"),
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
    blob = json.dumps(cleaned, sort_keys=True, ensure_ascii=False)
    if len(blob.encode("utf-8")) > _MAX_EVIDENCE_BYTES:
        cleaned["description"] = _truncate_text(cleaned.get("description"))
        cleaned["match_preview"] = _truncate_text(cleaned.get("match_preview"))
        blob = json.dumps(cleaned, sort_keys=True, ensure_ascii=False)
    return blob


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
            "gitleaks_parser.evidence_sidecar_write_failed",
            extra={
                "event": "gitleaks_parser_evidence_sidecar_write_failed",
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
                "gitleaks_parser.canonical_read_failed",
                extra={
                    "event": "gitleaks_parser_canonical_read_failed",
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
        rule_id = _string_field(raw, "RuleID")
        file_path = _string_field(raw, "File")
        if rule_id is None or file_path is None:
            _logger.warning(
                "gitleaks_parser.result_missing_field",
                extra={
                    "event": "gitleaks_parser_result_missing_field",
                    "tool_id": tool_id,
                    "missing": "RuleID" if rule_id is None else "File",
                },
            )
            continue
        description = _string_field(raw, "Description")
        severity = _classify_severity(rule_id=rule_id, description=description or "")
        match_raw = _string_field(raw, "Match")
        secret_raw = _string_field(raw, "Secret")
        match_preview = redact_secret(match_raw)
        secret_preview = redact_secret(secret_raw)
        tags = _extract_tags(raw.get("Tags"))
        yield {
            "rule_id": rule_id,
            "description": description,
            "file": file_path,
            "start_line": _coerce_int(raw.get("StartLine")) or 0,
            "end_line": _coerce_int(raw.get("EndLine")),
            "start_column": _coerce_int(raw.get("StartColumn")),
            "end_column": _coerce_int(raw.get("EndColumn")),
            "commit": _string_field(raw, "Commit"),
            "author": _string_field(raw, "Author"),
            "email": _string_field(raw, "Email"),
            "date": _string_field(raw, "Date"),
            "entropy": _coerce_float(raw.get("Entropy")),
            "tags": tags,
            "fingerprint": _string_field(raw, "Fingerprint"),
            "severity": severity,
            "match_preview": match_preview,
            "secret_preview": secret_preview,
            "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
        }


def _classify_severity(*, rule_id: str, description: str) -> str:
    haystack = f"{rule_id.lower()} {description.lower()}"
    if any(token in haystack for token in _CRITICAL_KEYWORDS):
        return "critical"
    if any(token in haystack for token in _HIGH_KEYWORDS):
        return "high"
    return "medium"


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


def _extract_tags(raw: Any) -> list[str]:
    if not isinstance(raw, list):
        return []
    out: list[str] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            out.append(item.strip())
    return sorted(set(out))


def _truncate_text(text: str | None) -> str | None:
    if text is None or text == "":
        return None
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= _MAX_EVIDENCE_BYTES // 4:
        return text
    truncated = encoded[: _MAX_EVIDENCE_BYTES // 4].decode("utf-8", errors="replace")
    return truncated + "...[truncated]"


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_gitleaks_json",
]
