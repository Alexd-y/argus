"""Parser for ``mongodb_probe`` JSON output (ARG-032 batch 4c).

The ``mongodb_probe`` wrapper invokes ``mongo --quiet --eval 'db.serverStatus()'``
against an unauthenticated MongoDB target and serialises the response
to ``/out/mongo_info.json``.  Canonical record shape (truncated)::

    {
      "host": "10.0.0.10:27017",
      "version": "4.4.6",
      "auth_required": false,
      "is_master": true,
      "databases": [{"name": "admin"}, {"name": "users"}]
    }

Findings:

* MISCONFIG (HIGH) when ``auth_required`` is ``false`` (CWE-306,
  Missing Authentication for Critical Function).
* INFO per discovered database name when ``auth_required`` is
  ``false`` and ``databases`` is non-empty.
* INFO with the server version even when authentication is enabled,
  so the operator has a fingerprint for downstream CVE matching.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    SSVCDecision,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "mongodb_probe_findings.jsonl"
_CANONICAL_NAME: Final[str] = "mongo_info.json"
_MAX_FINDINGS: Final[int] = 1_000

# Allow letters/digits/dots/hyphens/colons (host:port).  This is intentionally
# lenient — the wrapper resolves the host upstream so we trust the value
# is well-formed but still strip any control bytes.
_HOST_SANITISE_RE: Final[re.Pattern[str]] = re.compile(r"[^A-Za-z0-9.\-:_]+")


_DedupKey: TypeAlias = tuple[str, str, str]


def parse_mongodb_probe(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate mongodb_probe JSON output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_NAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, dict):
        return []
    host = _sanitise_host(payload.get("host"))
    if not host:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for record in _iter_findings(payload, host=host):
        record_host = str(record["host"])
        kind = str(record["kind"])
        subject = str(record["subject"])
        category_value = record["category"]
        cvss_value = record["cvss"]
        if not isinstance(category_value, FindingCategory) or not isinstance(
            cvss_value, (int, float)
        ):
            continue
        key: _DedupKey = (record_host, kind, subject)
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(category_value, float(cvss_value))
        evidence = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "mongodb_probe.cap_reached",
                extra={
                    "event": "mongodb_probe_cap_reached",
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


def _sanitise_host(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return _HOST_SANITISE_RE.sub("", value).strip(":._-").lower()


def _iter_findings(
    payload: dict[str, Any], *, host: str
) -> Iterator[dict[str, object]]:
    auth_required = bool(payload.get("auth_required"))
    version = payload.get("version") if isinstance(payload.get("version"), str) else ""
    if version:
        yield {
            "host": host,
            "kind": "version_disclosed",
            "subject": version,
            "category": FindingCategory.INFO,
            "cvss": 0.0,
            "auth_required": auth_required,
        }
    if not auth_required:
        yield {
            "host": host,
            "kind": "missing_authentication",
            "subject": "mongodb",
            "category": FindingCategory.MISCONFIG,
            "cvss": 9.1,
            "auth_required": False,
        }
        databases = payload.get("databases")
        if isinstance(databases, list):
            for entry in databases:
                if isinstance(entry, dict):
                    name = entry.get("name")
                elif isinstance(entry, str):
                    name = entry
                else:
                    continue
                if not isinstance(name, str) or not name.strip():
                    continue
                yield {
                    "host": host,
                    "kind": "database_listed",
                    "subject": name.strip().lower(),
                    "category": FindingCategory.INFO,
                    "cvss": 0.0,
                    "auth_required": False,
                }


def _build_finding(category: FindingCategory, cvss: float) -> FindingDTO:
    if category is FindingCategory.MISCONFIG:
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[306, 285, 200],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=cvss,
            confidence=ConfidenceLevel.CONFIRMED,
            ssvc_decision=SSVCDecision.ACT,
            owasp_wstg=["WSTG-CONF-04", "WSTG-ATHN-01"],
            mitre_attack=["T1190"],
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.CONFIRMED,
        owasp_wstg=["WSTG-INFO-02", "WSTG-INFO-08"],
    )


def _build_evidence(record: dict[str, object], *, tool_id: str) -> str:
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "host": record["host"],
        "kind": record["kind"],
        "subject": record["subject"],
        "auth_required": record["auth_required"],
        "fingerprint_hash": stable_hash_12(
            f"mongodb_probe|{record['host']}|{record['kind']}|{record['subject']}"
        ),
    }
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_mongodb_probe",
]
