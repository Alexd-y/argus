"""Parser for ``bloodhound_python`` collector logs (Backlog/dev1_md §4.17 — ARG-022).

``bloodhound-python`` is the Python-based BloodHound collector (a.k.a.
``BloodHound.py``).  When invoked with ``-c All --zip`` it collects
groups, sessions, ACLs, object properties, and trusts, then archives
the JSON files into ``{out_dir}/bloodhound/<timestamp>_BloodHound.zip``.

Stdout follows a logger-prefixed format::

    INFO: Found AD domain: contoso.local
    INFO: Connecting to LDAP server: dc01.contoso.local
    INFO: Found 1 domains
    INFO: Connecting to GC LDAP server: dc01.contoso.local
    INFO: Found 12 trusts
    INFO: Done in 00M 12S
    [+] Compressing output into 20260419120000_BloodHound.zip

The parser is **observability-only** — BloodHound's value lies in the
ZIP archive itself, which the §11 evidence pipeline ships verbatim.
This parser surfaces:

* one INFO :class:`FindingDTO` per ZIP archive marker
  (``Compressing output into <name>.zip`` or
  ``INFO: Wrote <name>.zip`` lines), capturing path + timestamp metadata;
* the AD domain context discovered on the wire (``Found AD domain: ...``);
* counts of users / groups / computers / sessions / trusts when
  surfaced in the log.

Severity is :class:`ConfidenceLevel.SUSPECTED` and CVSS is
:data:`SENTINEL_CVSS_SCORE` (0.0).  CWE-200 + CWE-269 + CWE-284 reflect
the information-disclosure / privilege-escalation surface of an AD
collection dataset.

The full BloodHound binary JSON parser is intentionally **deferred** —
the ZIP is opaque to ARGUS and consumed by upstream BloodHound CE.
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
    MAX_STDOUT_BYTES,
    SENTINEL_CVSS_SCORE,
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    safe_decode,
    stable_hash_12,
)
from src.sandbox.parsers._text_base import redact_hashes_in_evidence

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "bloodhound_python_findings.jsonl"
_MAX_FINDINGS: Final[int] = 50


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------


_DOMAIN_RE: Final[re.Pattern[str]] = re.compile(
    r"Found AD domain:\s*(?P<domain>\S+)",
    re.IGNORECASE,
)
_ZIP_MARKER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?:Compressing output into|Wrote)\s+"
    r"(?P<zip>(?:[A-Za-z]:\\|/)?[^\s\"']+\.zip)",
    re.IGNORECASE,
)
_COUNT_RE: Final[re.Pattern[str]] = re.compile(
    r"Found\s+(?P<count>\d+)\s+(?P<thing>users|groups|computers|sessions|trusts|gpos|domains|ous)",
    re.IGNORECASE,
)
_DC_RE: Final[re.Pattern[str]] = re.compile(
    r"Connecting to (?:GC )?LDAP server:\s*(?P<dc>\S+)",
    re.IGNORECASE,
)


DedupKey: TypeAlias = tuple[str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_bloodhound_python(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Surface a single INFO marker per BloodHound ZIP collected."""
    text = safe_decode(stdout, limit=MAX_STDOUT_BYTES)
    text_err = safe_decode(stderr, limit=MAX_STDOUT_BYTES)
    combined = "\n".join(filter(None, (text, text_err)))
    if not combined:
        return []
    summary = _summarise(combined)
    if not summary["zips"] and not summary["domain"]:
        return []
    records = list(_build_records(summary))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Summarisation
# ---------------------------------------------------------------------------


def _summarise(text: str) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "domain": "",
        "dcs": [],
        "zips": [],
        "counts": {},
    }
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if not summary["domain"]:
            domain_match = _DOMAIN_RE.search(line)
            if domain_match is not None:
                summary["domain"] = domain_match.group("domain").strip().rstrip(".")
        dc_match = _DC_RE.search(line)
        if dc_match is not None:
            dc = dc_match.group("dc").strip()
            if dc not in summary["dcs"]:
                summary["dcs"].append(dc)
        zip_match = _ZIP_MARKER_RE.search(line)
        if zip_match is not None:
            zip_path = zip_match.group("zip").strip().strip("'\"")
            if zip_path not in summary["zips"]:
                summary["zips"].append(zip_path)
        for count_match in _COUNT_RE.finditer(line):
            thing = count_match.group("thing").lower()
            try:
                summary["counts"][thing] = int(count_match.group("count"))
            except ValueError:
                continue
    return summary


def _build_records(summary: dict[str, Any]) -> Iterator[dict[str, Any]]:
    domain = summary["domain"]
    dcs = list(summary["dcs"])
    counts = dict(summary["counts"])
    if summary["zips"]:
        for zip_path in summary["zips"]:
            yield {
                "kind": "bloodhound_zip",
                "domain": domain,
                "dcs": dcs,
                "zip_path": zip_path,
                "counts": counts,
            }
    else:
        yield {
            "kind": "bloodhound_collection_run",
            "domain": domain,
            "dcs": dcs,
            "zip_path": "",
            "counts": counts,
        }


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
    keyed: list[tuple[DedupKey, FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (record["kind"], record.get("zip_path", ""))
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding()
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            break
    keyed.sort(key=lambda item: item[0])
    if keyed:
        _persist_sidecar(
            artifacts_dir,
            tool_id=tool_id,
            evidence_records=[blob for _, _, blob in keyed],
        )
    return [finding for _, finding, _ in keyed]


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200, 269, 284],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=SENTINEL_CVSS_SCORE,
        confidence=ConfidenceLevel.SUSPECTED,
        ssvc_decision=SSVCDecision.TRACK,
        owasp_wstg=["WSTG-INFO-05", "WSTG-ATHZ-01"],
        mitre_attack=["T1087.002", "T1482"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "domain": record.get("domain"),
        "domain_controllers": list(record.get("dcs") or []),
        "zip_path": record.get("zip_path"),
        "object_counts": record.get("counts") or {},
        "synthetic_id": stable_hash_12(
            f"{record.get('domain', '')}::{record.get('zip_path', '')}"
        ),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value in (None, "", [], {}):
            continue
        cleaned[key] = value
    string_values = {k: v for k, v in cleaned.items() if isinstance(v, str)}
    cleaned.update(redact_hashes_in_evidence(string_values))
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


def _persist_sidecar(
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
            "bloodhound_python_parser.evidence_sidecar_write_failed",
            extra={
                "event": "bloodhound_python_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_bloodhound_python",
]
