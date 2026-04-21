"""Parser for ``redis_cli_probe`` text output (ARG-032 batch 4c).

The ``redis_cli_probe`` wrapper invokes ``redis-cli -h <host> INFO``
(optionally with ``CONFIG GET *`` and ``CLIENT LIST``) and pipes the
key/value pairs to ``/out/redis_info.txt``.  Canonical line shape::

    # Server
    redis_version:6.2.6
    redis_mode:standalone
    os:Linux 5.15.0
    # Replication
    role:master
    connected_slaves:0
    # Clients
    requirepass:false

Findings:

* MISCONFIG (HIGH) when ``requirepass`` is ``false`` (CWE-306).
* INFO with the redis version and OS string for downstream CVE
  matching.
* INFO when ``maxmemory:0`` (no memory cap) — small risk but useful
  context.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Final, TypeAlias

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
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    parse_kv_lines,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "redis_cli_probe_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("redis_info.txt", "redis.txt")
_MAX_FINDINGS: Final[int] = 1_000

_TRUTHY: Final[frozenset[str]] = frozenset({"yes", "true", "1", "on"})
_FALSY: Final[frozenset[str]] = frozenset({"no", "false", "0", "off", ""})


_DedupKey: TypeAlias = tuple[str, str]


def parse_redis_cli_probe(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate redis-cli ``INFO`` output into FindingDTOs."""
    del stderr
    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=_CANONICAL_NAMES,
        tool_id=tool_id,
    )
    if not text:
        return []
    info = dict(parse_kv_lines(text, sep=":"))

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for record in _iter_findings(info):
        kind = str(record["kind"])
        subject = str(record["subject"])
        category_value = record["category"]
        cvss_value = record["cvss"]
        if not isinstance(category_value, FindingCategory) or not isinstance(
            cvss_value, (int, float)
        ):
            continue
        key: _DedupKey = (kind, subject)
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(category_value, float(cvss_value))
        evidence = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "redis_cli_probe.cap_reached",
                extra={
                    "event": "redis_cli_probe_cap_reached",
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


def _iter_findings(info: dict[str, str]) -> Iterator[dict[str, object]]:
    requirepass = (info.get("requirepass") or "").strip().lower()
    if requirepass in _FALSY:
        yield {
            "kind": "missing_password",
            "subject": "redis",
            "category": FindingCategory.MISCONFIG,
            "cvss": 9.1,
            "value": requirepass,
        }
    elif requirepass not in _TRUTHY:
        yield {
            "kind": "password_state_unknown",
            "subject": "redis",
            "category": FindingCategory.INFO,
            "cvss": 0.0,
            "value": requirepass,
        }
    version = (info.get("redis_version") or "").strip()
    if version:
        yield {
            "kind": "version_disclosed",
            "subject": version,
            "category": FindingCategory.INFO,
            "cvss": 0.0,
            "value": version,
        }
    role = (info.get("role") or "").strip()
    if role:
        yield {
            "kind": "role_observed",
            "subject": role.lower(),
            "category": FindingCategory.INFO,
            "cvss": 0.0,
            "value": role,
        }
    maxmemory = (info.get("maxmemory") or "").strip()
    if maxmemory == "0":
        yield {
            "kind": "memory_uncapped",
            "subject": "maxmemory",
            "category": FindingCategory.MISCONFIG,
            "cvss": 4.3,
            "value": maxmemory,
        }


def _build_finding(category: FindingCategory, cvss: float) -> FindingDTO:
    if category is FindingCategory.MISCONFIG and cvss >= 7.0:
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
    if category is FindingCategory.MISCONFIG:
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[16, 200],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=cvss,
            confidence=ConfidenceLevel.SUSPECTED,
            ssvc_decision=SSVCDecision.TRACK,
            owasp_wstg=["WSTG-CONF-04"],
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
        "kind": record["kind"],
        "subject": record["subject"],
        "value": record["value"],
        "fingerprint_hash": stable_hash_12(
            f"redis_cli_probe|{record['kind']}|{record['subject']}"
        ),
    }
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_redis_cli_probe",
]
