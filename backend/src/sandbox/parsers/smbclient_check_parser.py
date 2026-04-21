"""Parser for ``smbclient -L`` share listings (Backlog/dev1_md §4.12 — ARG-022).

The wrapper runs ``smbclient -L //{host} -U {user}%{pass}`` and pipes
the output to ``{out_dir}/smb_list.txt``.  Samba 4.x emits the
canonical share-listing block::

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        netlogon        Disk
        sysvol          Disk
        Shared          Disk      Public share
    Reconnecting with SMB1 for workgroup listing.
        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            DC01

The parser produces one :class:`FindingDTO` per discovered share with
severity:

* MEDIUM if the share name matches ``ADMIN$`` / ``C$`` / ``D$`` / etc
  (administrative shares exposed) → CWE-200 + CWE-285;
* LOW for everything else (information-disclosure baseline).

Sidecar
-------
``smbclient_findings.jsonl`` records share name + type + comment.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "smbclient_findings.jsonl"
_MAX_FINDINGS: Final[int] = 1_000


_ADMIN_SHARE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:[A-Z]\$|ADMIN\$|IPC\$|PRINT\$|FAX\$|NETLOGON|SYSVOL)$",
    re.IGNORECASE,
)


_CVSS_ADMIN_SHARE: Final[float] = 6.5
_CVSS_INFO_SHARE: Final[float] = 3.7


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------


# ``Sharename       Type      Comment`` header detector.
_SHARE_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*Sharename\s+Type\s+Comment\s*$",
    re.IGNORECASE,
)
# Three-column rows whose Type is one of the well-known SMB types.
_SHARE_ROW_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?P<share>\S+)\s+(?P<type>Disk|IPC|Printer|Disk\(IPC\))\s*"
    r"(?P<comment>.*?)\s*$",
    re.IGNORECASE,
)
_SEPARATOR_RE: Final[re.Pattern[str]] = re.compile(r"^\s*---+\s+---+(?:\s+---+)?\s*$")


DedupKey: TypeAlias = tuple[str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_smbclient_check(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate smbclient share listings into INFO / MISCONFIG FindingDTOs."""
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
    """Walk the text honouring the share-table boundaries."""
    in_share_section = False
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            in_share_section = False
            continue
        if _SHARE_HEADER_RE.match(line):
            in_share_section = True
            continue
        if _SEPARATOR_RE.match(line):
            continue
        if not in_share_section:
            continue
        match = _SHARE_ROW_RE.match(line)
        if match is None:
            continue
        share = match.group("share").strip()
        if share.startswith("---"):
            continue
        share_type = match.group("type").strip()
        comment = match.group("comment").strip()
        is_admin = bool(_ADMIN_SHARE_RE.match(share))
        yield {
            "kind": "smb_admin_share" if is_admin else "smb_share",
            "share": share,
            "share_type": share_type,
            "comment": comment,
            "admin_share": is_admin,
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
        key: DedupKey = (record["kind"], record["share"].lower())
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (-1 if record["admin_share"] else 0, record["share"].lower())
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
    if record.get("admin_share"):
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[200, 285],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=_CVSS_ADMIN_SHARE,
            confidence=ConfidenceLevel.CONFIRMED,
            ssvc_decision=SSVCDecision.ATTEND,
            owasp_wstg=["WSTG-INFO-04", "WSTG-CONF-05"],
            mitre_attack=["T1135", "T1021.002"],
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_CVSS_INFO_SHARE,
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=SSVCDecision.TRACK,
        owasp_wstg=["WSTG-INFO-04"],
        mitre_attack=["T1135"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "share": record.get("share"),
        "share_type": record.get("share_type"),
        "comment": record.get("comment"),
        "admin_share": bool(record.get("admin_share")),
        "synthetic_id": stable_hash_12(
            f"{record.get('share', '').lower()}::{record.get('share_type', '')}"
        ),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value in (None, "") and key != "admin_share":
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
            "smbclient_check_parser.evidence_sidecar_write_failed",
            extra={
                "event": "smbclient_check_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_smbclient_check",
]
