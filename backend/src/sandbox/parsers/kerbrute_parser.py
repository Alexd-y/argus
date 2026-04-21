"""Parser for ``kerbrute`` username-enumeration output (Backlog/dev1_md §4.12 — ARG-022).

``kerbrute`` performs Kerberos pre-authentication probes against the
target KDC.  In ``userenum`` mode it emits one line per discovered
account on stdout::

    2026/04/19 12:00:00 >  Using KDC(s):
    2026/04/19 12:00:00 >    dc01.contoso.local:88
    2026/04/19 12:00:00 >  [+] VALID USERNAME:    administrator@contoso.local
    2026/04/19 12:00:00 >  [+] VALID USERNAME:    svc-backup@contoso.local
    2026/04/19 12:00:00 >  [+] VALID USERNAME (NO PREAUTH):  asreproast.user@contoso.local
    2026/04/19 12:00:01 >  Done! Tested 1234 usernames (2 valid) in 0.910 seconds

The parser surfaces:

* ``[+] VALID USERNAME: <user>@<domain>`` → :class:`FindingCategory.AUTH`,
  CWE-204 (Observable Response Discrepancy) + CWE-200, severity HIGH.
* ``[+] VALID USERNAME (NO PREAUTH): <user>@<domain>`` → AS-REP
  roastable account, severity CRITICAL (CWE-287, CVSS 8.8).  These
  accounts can be ticketed without a password and cracked offline.

The parser is **idempotent** and **deterministic**:

* dedup via ``(account, no_preauth)``;
* sort by domain → user → no_preauth flag.

Sidecar
-------
Written to ``kerbrute_findings.jsonl`` with one JSON record per
discovered principal.  Account names are kept verbatim (they are
identifiers, not credential material); any AES key fragments that
might appear in upgraded ``passwordspray`` mode pass through
:func:`redact_hash_string`.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "kerbrute_findings.jsonl"
_MAX_FINDINGS: Final[int] = 5_000

_CVSS_VALID_USER: Final[float] = 5.3
_CVSS_NO_PREAUTH: Final[float] = 8.8


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------


_VALID_USER_RE: Final[re.Pattern[str]] = re.compile(
    r"\[\+\]\s*VALID USERNAME"
    r"(?P<no_preauth>\s*\(NO\s*PREAUTH\))?"
    r"\s*:\s*(?P<account>[^\s@]+@[^\s]+)\s*$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public type aliases
# ---------------------------------------------------------------------------


DedupKey: TypeAlias = tuple[str, int]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_kerbrute(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate kerbrute valid-user lines into AUTH FindingDTOs."""
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
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _VALID_USER_RE.search(line)
        if match is None:
            continue
        account = match.group("account").strip()
        if "@" not in account:
            continue
        user, domain = account.rsplit("@", 1)
        if not user or not domain:
            continue
        no_preauth = match.group("no_preauth") is not None
        yield {
            "kind": "kerbrute_no_preauth" if no_preauth else "kerbrute_valid_user",
            "account": account,
            "user": user,
            "domain": domain,
            "no_preauth": no_preauth,
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
    keyed: list[tuple[tuple[int, str, str, int], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (record["account"], int(record["no_preauth"]))
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            -1 if record["no_preauth"] else 0,
            record["domain"],
            record["user"],
            int(record["no_preauth"]),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "kerbrute_parser.cap_reached",
                extra={
                    "event": "kerbrute_parser_cap_reached",
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
    no_preauth = bool(record.get("no_preauth"))
    return make_finding_dto(
        category=FindingCategory.AUTH,
        cwe=[287, 200] if no_preauth else [200, 204],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_CVSS_NO_PREAUTH if no_preauth else _CVSS_VALID_USER,
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=SSVCDecision.ATTEND if no_preauth else SSVCDecision.TRACK_STAR,
        owasp_wstg=["WSTG-ATHN-03"],
        mitre_attack=["T1558.004", "T1087.002"] if no_preauth else ["T1087.002"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "account": record.get("account"),
        "user": record.get("user"),
        "domain": record.get("domain"),
        "no_preauth": bool(record.get("no_preauth")),
        "synthetic_id": stable_hash_12(
            f"{record.get('account', '')}::{int(bool(record.get('no_preauth')))}"
        ),
    }
    cleaned: dict[str, Any] = {k: v for k, v in payload.items() if v not in (None, "")}
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
            "kerbrute_parser.evidence_sidecar_write_failed",
            extra={
                "event": "kerbrute_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_kerbrute",
]
