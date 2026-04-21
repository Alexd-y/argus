"""Parser for ``trufflehog`` ``--json`` output (Backlog/dev1_md §4.16 — ARG-029).

Truffle Security trufflehog scans the source tree at ``{path}`` (the
sandbox /in mount) using ~750 detectors.  The catalog wires it as
``trufflehog filesystem {path} --json --no-update --no-verification >
{out_dir}/trufflehog.json`` so the file is canonical JSONL — one JSON
object per line, each describing a single secret hit:

.. code-block:: json

    {
      "DetectorName":     "AWS",
      "DetectorType":     2,
      "Verified":         false,
      "VerificationError":"",
      "Raw":              "AKIAIOSFODNN7EXAMPLE",
      "RawV2":            "AKIAIOSFODNN7EXAMPLE:wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "Redacted":         "AKIAIOSFODNN7EXAMPLE",
      "ExtraData":        {"account": "123456789012"},
      "DecoderName":      "PLAIN",
      "SourceMetadata": {
        "Data": {
          "Filesystem": {
            "file": "src/config/dev.env",
            "line": 12
          }
        }
      },
      "SourceID":         12345,
      "SourceName":       "trufflehog - filesystem",
      "SourceType":       15
    }

CRITICAL — secret redaction (security-auditor gated)
----------------------------------------------------

Trufflehog is the **only** parser in the catalog that legitimately
receives raw cleartext credentials surfaced by detectors.  Every
record passes through :func:`src.sandbox.parsers._base.redact_secret`
on three fields **before** any DTO construction or sidecar
persistence:

* ``Raw``    — primary detected secret blob.
* ``RawV2``  — multi-part secret identifier (e.g. AWS key + secret).
* ``Redacted`` — vendor-supplied redaction; we still re-redact in
  case future trufflehog releases stop redacting it themselves.

The ``Verified`` flag and ``DetectorName`` / ``DetectorType`` are kept
verbatim because they carry no secret material.  ``VerificationError``
is also preserved (text only).

The integration test :mod:`tests.integration.sandbox.parsers.\
test_arg029_dispatch` enforces a hard guardrail: the sidecar JSONL
file must contain ZERO matches against ``[A-Za-z0-9/_+]{40,}`` (the
canonical AWS-secret-shape regex) for the trufflehog fixture.  This
gate fails the build if any future change re-introduces raw secret
material into the evidence path.

Translation rules
-----------------

* **Severity** is detector-derived.  Mapping:

  - ``aws-*`` / ``gcp-*`` / ``azure-*`` / ``stripe-live-*`` /
    ``private-key`` / ``rsa-private`` → ``critical`` (CVSS 9.5).
  - Generic API tokens (``slack``, ``github``, ``gitlab``, ``jwt``,
    ``twilio``, ``sendgrid``, ``shopify``, ``discord``, ``datadog``)
    → ``high`` (CVSS 8.0).
  - All other detectors → ``medium`` (CVSS 6.0).
  - ``Verified=true`` always escalates to AT LEAST ``high`` — a
    verified credential is by definition exploitable today.

* **Confidence** — :class:`ConfidenceLevel.CONFIRMED` for verified
  secrets, :class:`ConfidenceLevel.LIKELY` otherwise.  Trufflehog
  matches are entropy + regex driven; the actual *presence* of a
  secret is rarely in doubt, so SUSPECTED is reserved for "we cannot
  even tell what kind of secret this is" — which never happens for
  trufflehog records that survived ``--no-verification`` JSON output.

* **Category** — :class:`FindingCategory.SECRET_LEAK` for every
  finding this parser yields.

* **CWE** — pinned at ``[798, 312]``: CWE-798 (Hard-coded
  Credentials) is canonical, CWE-312 (Cleartext Storage of Sensitive
  Information) tags the second-order risk that committed secrets
  create.

Dedup / cap / determinism
-------------------------

* Dedup key: ``(detector_name, file, line)`` — the same detector
  matching twice on the same line is one finding (re-runs); the same
  detector matching twice on different files is two.
* Cap: hard-limited to :data:`_MAX_FINDINGS = 5_000` so a noisy scan
  over a vendored ``node_modules/`` cannot exhaust worker memory.
* Output ordering: severity DESC, then ``detector_name`` / ``file`` /
  ``line`` ASC so two runs against the same fixture produce
  byte-identical findings + sidecar.

Sidecar
-------

Mirrored into ``artifacts_dir / "trufflehog_findings.jsonl"``.  Every
record carries the redacted previews ONLY — no raw secret bytes ever
land in the evidence file.
"""

from __future__ import annotations

import json
import logging
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
    redact_secret,
)
from src.sandbox.parsers._jsonl_base import (
    iter_jsonl_records,
    persist_jsonl_sidecar,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "trufflehog_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "trufflehog.json"
_MAX_FINDINGS: Final[int] = 5_000


_CWE_HARDCODED_CREDS: Final[int] = 798
_CWE_CLEARTEXT_STORAGE: Final[int] = 312


# Severity → CVSS anchor. Mirrors the Gitleaks parser pattern so
# downstream severity bucketing stays consistent across secret-leak tools.
_SEVERITY_TO_CVSS: Final[dict[str, float]] = {
    "critical": 9.5,
    "high": 8.0,
    "medium": 6.0,
    "low": 3.5,
}


_SEVERITY_RANK: Final[dict[str, int]] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


# Detector keyword → severity. Order matters (first match wins). The
# token list is normalised to lower-case before comparison so trufflehog's
# "AWS" / "Aws" / "aws" all collapse onto the same bucket.
_CRITICAL_DETECTORS: Final[tuple[str, ...]] = (
    "aws",
    "gcp",
    "google",
    "azure",
    "stripe-live",
    "stripelive",
    "stripeapikey",
    "rsa",
    "private",
    "privatekey",
    "ssh",
    "pgp",
)
_HIGH_DETECTORS: Final[tuple[str, ...]] = (
    "github",
    "gitlab",
    "slack",
    "jwt",
    "twilio",
    "sendgrid",
    "shopify",
    "discord",
    "datadog",
    "circleci",
    "stripe",
    "npm",
    "heroku",
    "mailgun",
    "okta",
)


DedupKey: TypeAlias = tuple[str, str, int]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_trufflehog_jsonl(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate trufflehog ``--json`` output into FindingDTOs."""
    del stderr
    records = list(
        _iter_normalised(
            iter_jsonl_records(
                stdout=stdout,
                artifacts_dir=artifacts_dir,
                canonical_name=_CANONICAL_FILENAME,
                tool_id=tool_id,
            ),
            tool_id=tool_id,
        )
    )
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
    keyed: list[tuple[tuple[int, str, str, int], FindingDTO, str]] = []
    for record in records:
        key = _dedup_key(record)
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        keyed.append((_sort_key(record), finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "trufflehog_parser.cap_reached",
                extra={
                    "event": "trufflehog_parser_cap_reached",
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


def _dedup_key(record: dict[str, Any]) -> DedupKey:
    return (
        str(record.get("detector_name") or ""),
        str(record.get("file") or ""),
        int(record.get("line") or 0),
    )


def _sort_key(record: dict[str, Any]) -> tuple[int, str, str, int]:
    severity = str(record.get("severity") or "medium")
    return (
        -_SEVERITY_RANK.get(severity, 0),
        str(record.get("detector_name") or ""),
        str(record.get("file") or ""),
        int(record.get("line") or 0),
    )


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    confidence = (
        ConfidenceLevel.CONFIRMED if record.get("verified") else ConfidenceLevel.LIKELY
    )
    return make_finding_dto(
        category=FindingCategory.SECRET_LEAK,
        cwe=[_CWE_HARDCODED_CREDS, _CWE_CLEARTEXT_STORAGE],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=float(record.get("cvss_v3_score") or 0.0),
        confidence=confidence,
        owasp_wstg=["WSTG-ATHN-06", "WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "trufflehog",
        "detector_name": record.get("detector_name"),
        "detector_type": record.get("detector_type"),
        "decoder_name": record.get("decoder_name"),
        "verified": record.get("verified"),
        "verification_error": record.get("verification_error"),
        "file": record.get("file"),
        "line": record.get("line"),
        "source_name": record.get("source_name"),
        "source_id": record.get("source_id"),
        "source_type": record.get("source_type"),
        "raw_preview": record.get("raw_preview"),
        "raw_v2_preview": record.get("raw_v2_preview"),
        "redacted_preview": record.get("redacted_preview"),
        "extra_keys": record.get("extra_keys"),
        "severity": record.get("severity"),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value is None:
            continue
        if isinstance(value, str | list) and not value:
            continue
        cleaned[key] = value
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Record normalisation
# ---------------------------------------------------------------------------


def _iter_normalised(
    raw_records: Iterator[dict[str, Any]],
    *,
    tool_id: str,
) -> Iterator[dict[str, Any]]:
    for raw in raw_records:
        detector_name = _string_field(raw, "DetectorName")
        if detector_name is None:
            _logger.warning(
                "trufflehog_parser.record_missing_field",
                extra={
                    "event": "trufflehog_parser_record_missing_field",
                    "tool_id": tool_id,
                    "missing": "DetectorName",
                },
            )
            continue
        verified = bool(raw.get("Verified"))
        severity = _classify_severity(detector_name=detector_name, verified=verified)
        file_path, line = _extract_source_location(raw)
        raw_preview = redact_secret(_string_field(raw, "Raw"))
        raw_v2_preview = redact_secret(_string_field(raw, "RawV2"))
        redacted_preview = redact_secret(_string_field(raw, "Redacted"))
        extra_keys = _extract_extra_keys(raw.get("ExtraData"))
        yield {
            "detector_name": detector_name,
            "detector_type": _coerce_int(raw.get("DetectorType")),
            "decoder_name": _string_field(raw, "DecoderName"),
            "verified": verified,
            "verification_error": _string_field(raw, "VerificationError"),
            "file": file_path,
            "line": line,
            "source_name": _string_field(raw, "SourceName"),
            "source_id": _coerce_int(raw.get("SourceID")),
            "source_type": _coerce_int(raw.get("SourceType")),
            "raw_preview": raw_preview,
            "raw_v2_preview": raw_v2_preview,
            "redacted_preview": redacted_preview,
            "extra_keys": extra_keys,
            "severity": severity,
            "cvss_v3_score": _SEVERITY_TO_CVSS.get(severity, 0.0),
        }


def _classify_severity(*, detector_name: str, verified: bool) -> str:
    haystack = detector_name.lower().replace("-", "").replace("_", "")
    severity = "medium"
    if any(token.replace("-", "") in haystack for token in _CRITICAL_DETECTORS):
        severity = "critical"
    elif any(token in haystack for token in _HIGH_DETECTORS):
        severity = "high"
    if verified and severity == "medium":
        return "high"
    return severity


def _extract_source_location(raw: dict[str, Any]) -> tuple[str, int]:
    """Return ``(file_path, line)`` from the SourceMetadata envelope."""
    metadata = raw.get("SourceMetadata")
    if not isinstance(metadata, dict):
        return "", 0
    data = metadata.get("Data")
    if not isinstance(data, dict):
        return "", 0
    for source_kind, payload in data.items():
        if not isinstance(payload, dict):
            continue
        del source_kind
        file_path = (
            _string_field(payload, "file")
            or _string_field(payload, "File")
            or _string_field(payload, "path")
            or _string_field(payload, "uri")
            or ""
        )
        line = _coerce_int(payload.get("line")) or _coerce_int(payload.get("Line")) or 0
        return file_path, line
    return "", 0


def _extract_extra_keys(raw: Any) -> list[str]:
    """Return sorted ``ExtraData`` keys (values are not surfaced).

    ``ExtraData`` may carry verification context such as AWS account
    numbers; we surface the *keys* (so analysts know there's auxiliary
    metadata to pivot on) but DROP the values, defence-in-depth in
    case a future detector starts shoving raw context there.
    """
    if not isinstance(raw, dict):
        return []
    return sorted(str(key) for key in raw.keys())


# ---------------------------------------------------------------------------
# Coercion helpers
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


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_trufflehog_jsonl",
]
