"""Parser for ``smbmap`` access-rights report (Backlog/dev1_md §4.2 — ARG-022).

``smbmap -H {ip} -R -q`` performs anonymous SMB enumeration and prints
a per-host header followed by share rows::

    [+] IP: 10.0.0.42:445   Name: dc01.contoso.local   Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        Public                                                  READ, WRITE     Public share
        Backups                                                 READ ONLY       Daily backups

Every recognised ``share + permissions`` row produces a single
:class:`FindingDTO` whose severity ladder is permission-driven:

* ``READ, WRITE`` (writable share) → HIGH (CWE-732 + CWE-200, CVSS 8.5).
* ``READ ONLY`` on **non-administrative** share → MEDIUM (CWE-200,
  CVSS 5.3).
* ``READ ONLY`` on ``IPC$`` / ``ADMIN$`` / ``NETLOGON`` / ``SYSVOL`` →
  LOW (legitimate baseline, CWE-200, CVSS 3.7).
* ``NO ACCESS`` → INFO (no finding emitted; logged only via dedup).

Sidecar
-------
``smbmap_findings.jsonl`` records host + share + permission + comment.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "smbmap_findings.jsonl"
_MAX_FINDINGS: Final[int] = 5_000


_BASELINE_SHARES: Final[frozenset[str]] = frozenset(
    {"ipc$", "admin$", "netlogon", "sysvol", "print$"}
)


_CVSS_WRITE: Final[float] = 8.5
_CVSS_READ_SENSITIVE: Final[float] = 5.3
_CVSS_BASELINE: Final[float] = 3.7


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------


_HOST_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"^\[\+\]\s*(?:IP|Host)\s*:\s*(?P<ip>[\d\.:a-fA-F]+)"
    r"(?:\s+Name\s*:\s*(?P<host>\S+))?"
    r"(?:\s+Status\s*:\s*(?P<status>.+?))?\s*$",
    re.IGNORECASE,
)
_SHARE_ROW_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?P<share>\S+?)\s{2,}"
    r"(?P<permission>NO ACCESS|READ ONLY|READ, WRITE|WRITE ONLY)"
    r"\s*(?P<comment>.*?)\s*$",
    re.IGNORECASE,
)
_TABLE_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*Disk\s+Permissions(?:\s+Comment)?\s*$",
    re.IGNORECASE,
)


DedupKey: TypeAlias = tuple[str, str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_smbmap(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate smbmap report rows into AUTH / MISCONFIG / INFO findings."""
    del stderr
    text = safe_decode(stdout, limit=MAX_STDOUT_BYTES)
    if not text:
        return []
    records = list(_iter_records(text))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Record extraction
# ---------------------------------------------------------------------------


def _iter_records(text: str) -> Iterator[dict[str, Any]]:
    current_host: dict[str, str] = {}
    in_table = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped:
            in_table = False
            continue
        host_match = _HOST_HEADER_RE.match(stripped)
        if host_match is not None:
            current_host = {
                "ip": host_match.group("ip").strip(),
                "host": (host_match.group("host") or "").strip(),
                "status": (host_match.group("status") or "").strip(),
            }
            in_table = False
            continue
        if _TABLE_HEADER_RE.match(line):
            in_table = True
            continue
        if not in_table:
            continue
        share_match = _SHARE_ROW_RE.match(line)
        if share_match is None:
            continue
        permission = share_match.group("permission").upper().strip()
        if permission == "NO ACCESS":
            continue
        share = share_match.group("share").strip()
        comment = share_match.group("comment").strip()
        yield {
            "kind": _classify_kind(permission, share),
            "ip": current_host.get("ip") or "",
            "host": current_host.get("host") or "",
            "status": current_host.get("status") or "",
            "share": share,
            "permission": permission,
            "comment": comment,
            "writable": permission in {"READ, WRITE", "WRITE ONLY"},
        }


def _classify_kind(permission: str, share: str) -> str:
    if permission in {"READ, WRITE", "WRITE ONLY"}:
        return "smb_writable_share"
    if share.lower() in _BASELINE_SHARES:
        return "smb_baseline_share"
    return "smb_readable_share"


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
    keyed: list[tuple[tuple[int, str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (
            record["ip"],
            record["share"].lower(),
            record["permission"],
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            -2
            if record["writable"]
            else (-1 if record["kind"] == "smb_readable_share" else 0),
            record["ip"],
            record["share"].lower(),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "smbmap_parser.cap_reached",
                extra={
                    "event": "smbmap_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
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
    if record["writable"]:
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[732, 200, 285],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=_CVSS_WRITE,
            confidence=ConfidenceLevel.CONFIRMED,
            ssvc_decision=SSVCDecision.ACT,
            owasp_wstg=["WSTG-CONF-05", "WSTG-INFO-04"],
            mitre_attack=["T1135", "T1021.002"],
        )
    if record["kind"] == "smb_readable_share":
        return make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[200, 285],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=_CVSS_READ_SENSITIVE,
            confidence=ConfidenceLevel.CONFIRMED,
            ssvc_decision=SSVCDecision.ATTEND,
            owasp_wstg=["WSTG-INFO-04"],
            mitre_attack=["T1135"],
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_CVSS_BASELINE,
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=SSVCDecision.TRACK,
        owasp_wstg=["WSTG-INFO-04"],
        mitre_attack=["T1135"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "ip": record.get("ip"),
        "host": record.get("host"),
        "status": record.get("status"),
        "share": record.get("share"),
        "permission": record.get("permission"),
        "comment": record.get("comment"),
        "writable": bool(record.get("writable")),
        "synthetic_id": stable_hash_12(
            f"{record.get('ip', '')}::{record.get('share', '').lower()}::"
            f"{record.get('permission', '')}"
        ),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value in (None, "") and key != "writable":
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
            "smbmap_parser.evidence_sidecar_write_failed",
            extra={
                "event": "smbmap_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_smbmap",
]
