"""Parser for ``enum4linux_ng`` legacy text output (Backlog/dev1_md §4.2 — ARG-022).

``enum4linux-ng -A {ip}`` performs an exhaustive SMB / NetBIOS / RPC
enumeration.  While the YAML wrapper enables ``-oJ`` (JSON output to
file), this parser intentionally targets the **stdout text path** —
the tool always echoes the legacy text report on stdout regardless of
``-oJ`` so we keep parser surface independent from the JSON format
churn between versions.

Sample text shape::

    ===================================
    | Target Information for 10.0.0.42 |
    ===================================
    [+] Target ........... 10.0.0.42
    [+] Username ......... ''
    [+] Random username .. 'YyTPbCuf'

    =====================================
    | Domain Information via SMB for 10.0.0.42 |
    =====================================
    [+] NetBIOS computer name ... DC01
    [+] Workgroup/Domain ........ CONTOSO
    [+] FQDN .................... dc01.contoso.local
    [+] Domain SID .............. S-1-5-21-...

    ====================================
    | Users via RPC on 10.0.0.42 |
    ====================================
    [+] Found user 'administrator' (RID: 500)
    [+] Found user 'svc-backup' (RID: 1108)

The parser surfaces:

* one INFO :class:`FindingDTO` per recognised section (capturing the
  ``key = value`` block);
* one MEDIUM :class:`FindingCategory.MISCONFIG` finding when the report
  contains the ``Null sessions allowed`` / ``Anonymous bind`` markers.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "enum4linux_ng_findings.jsonl"
_MAX_FINDINGS: Final[int] = 1_000


_NULL_SESSION_TOKENS: Final[tuple[str, ...]] = (
    "null sessions allowed",
    "null session is possible",
    "anonymous bind allowed",
    "anonymous login allowed",
)


_CVSS_NULL_SESSION: Final[float] = 6.5
_CVSS_INFO: Final[float] = 3.7


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------


# ``=== <name> ===`` or ``| <name> |`` style headers.  We accept any line
# whose stripped form is wholly composed of ``=`` chars (length ≥ 3) as a
# divider so the next ``| Name |`` line is captured as the section title.
_DIVIDER_RE: Final[re.Pattern[str]] = re.compile(r"^={3,}$")
_PIPE_HEADER_RE: Final[re.Pattern[str]] = re.compile(r"^\|\s*(?P<title>.+?)\s*\|\s*$")
_BRACKET_KV_RE: Final[re.Pattern[str]] = re.compile(
    r"^\[(?P<status>[+\-*?])\]\s*(?P<key>[^.]+?)\s*\.{2,}\s*(?P<value>.*?)\s*$"
)
_FOUND_USER_RE: Final[re.Pattern[str]] = re.compile(
    r"^\[\+\]\s*Found\s+(?:user|group)\s*['\"]?(?P<name>[^'\"]+)['\"]?"
    r"(?:\s*\(RID:\s*(?P<rid>\d+)\))?\s*$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public type aliases
# ---------------------------------------------------------------------------


DedupKey: TypeAlias = tuple[str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_enum4linux_ng(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate enum4linux-ng legacy text output into FindingDTOs."""
    del stderr
    text = safe_decode(stdout, limit=MAX_STDOUT_BYTES)
    if not text:
        return []
    sections = list(_iter_sections(text))
    if not sections:
        return []
    return _emit(sections, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Section walker
# ---------------------------------------------------------------------------


def _iter_sections(text: str) -> Iterator[dict[str, Any]]:
    section_title: str = "preamble"
    section_data: dict[str, str] = {}
    members: list[str] = []
    null_session = False
    pending_divider = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            continue
        if _DIVIDER_RE.match(stripped):
            if section_data or members or pending_divider:
                yield _build_section(
                    section_title,
                    section_data,
                    members,
                    null_session,
                )
                section_data = {}
                members = []
                null_session = False
            pending_divider = True
            continue
        header = _PIPE_HEADER_RE.match(stripped)
        if header is not None and pending_divider:
            section_title = header.group("title").strip()
            pending_divider = False
            continue
        pending_divider = False
        kv = _BRACKET_KV_RE.match(stripped)
        if kv is not None:
            key = kv.group("key").strip()
            value = kv.group("value").strip().strip("'\"")
            if key:
                section_data[key] = value
                if any(token in value.lower() for token in _NULL_SESSION_TOKENS):
                    null_session = True
            continue
        user_match = _FOUND_USER_RE.match(stripped)
        if user_match is not None:
            name = user_match.group("name").strip()
            rid = user_match.group("rid")
            members.append(f"{name}" + (f" (RID:{rid})" if rid else ""))
            continue
        if any(token in stripped.lower() for token in _NULL_SESSION_TOKENS):
            null_session = True
    if section_data or members or null_session:
        yield _build_section(section_title, section_data, members, null_session)


def _build_section(
    title: str,
    data: dict[str, str],
    members: list[str],
    null_session: bool,
) -> dict[str, Any]:
    return {
        "kind": "enum4linux_null_session" if null_session else "enum4linux_section",
        "section": title,
        "fields": dict(data),
        "members": list(members),
        "null_session": null_session,
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
    keyed: list[tuple[tuple[int, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (record["kind"], record["section"].lower())
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (-1 if record["null_session"] else 0, record["section"].lower())
        keyed.append((sort_key, finding, evidence_blob))
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


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    if record.get("null_session"):
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[200, 287, 285],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=_CVSS_NULL_SESSION,
            confidence=ConfidenceLevel.CONFIRMED,
            ssvc_decision=SSVCDecision.ATTEND,
            owasp_wstg=["WSTG-INFO-04", "WSTG-CONF-05"],
            mitre_attack=["T1135", "T1087.002"],
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_CVSS_INFO,
        confidence=ConfidenceLevel.LIKELY,
        ssvc_decision=SSVCDecision.TRACK,
        owasp_wstg=["WSTG-INFO-04"],
        mitre_attack=["T1135"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "section": record.get("section"),
        "fields": dict(record.get("fields") or {}),
        "members": list(record.get("members") or []),
        "null_session": bool(record.get("null_session")),
        "synthetic_id": stable_hash_12(
            f"{record.get('section', '').lower()}::"
            f"{int(bool(record.get('null_session')))}"
        ),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value in (None, "", [], {}) and key != "null_session":
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
            "enum4linux_ng_parser.evidence_sidecar_write_failed",
            extra={
                "event": "enum4linux_ng_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_enum4linux_ng",
]
