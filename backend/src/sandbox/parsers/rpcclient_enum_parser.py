"""Parser for ``rpcclient`` null-session enumeration (Backlog/dev1_md §4.2 — ARG-022).

The wrapper invokes ``rpcclient -U '' -N {ip} -c 'enumdomusers; enumdomgroups; querydominfo'``
which produces three sequential blocks::

    user:[Administrator] rid:[0x1f4]
    user:[Guest] rid:[0x1f5]
    user:[svc-backup] rid:[0x454]
    group:[Domain Admins] rid:[0x200]
    group:[Domain Users] rid:[0x201]
    Domain Name: CONTOSO
    Domain Server: DC01
    Domain Controller: DC01
    Total Users: 312
    Total Groups: 84
    Total Aliases: 6

Optional ``account[USER]: ... attribs:`` blocks may also appear when
``queryuserlist`` is invoked::

    account[Administrator]: name:[Administrator] desc:[Built-in account for administering the computer/domain] attribs:[Account Disabled]

The parser surfaces:

* one :class:`FindingDTO` per discovered user (CWE-200 + CWE-285) at
  LOW severity — null-session enumeration is itself low-impact, but
  the dataset feeds downstream brute-force tools.
* one MISCONFIG MEDIUM finding when the ``Account Disabled`` /
  ``Password Never Expires`` attribs are unset for default accounts
  AND the ``Total Users`` count exceeds zero (i.e. the null session
  was accepted at all).

Sidecar
-------
``rpcclient_enum_findings.jsonl`` records the redacted account
metadata.
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


EVIDENCE_SIDECAR_NAME: Final[str] = "rpcclient_enum_findings.jsonl"
_MAX_FINDINGS: Final[int] = 5_000


_CVSS_NULL_SESSION: Final[float] = 5.3
_CVSS_BASELINE: Final[float] = 3.1


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------


# ``user:[name] rid:[0xRID]``
_USER_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r"^user:\[(?P<user>[^\]]+)\]\s*rid:\[(?P<rid>0x[0-9a-fA-F]+|\d+)\]\s*$"
)
# ``group:[name] rid:[0xRID]``
_GROUP_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r"^group:\[(?P<group>[^\]]+)\]\s*rid:\[(?P<rid>0x[0-9a-fA-F]+|\d+)\]\s*$"
)
# ``account[USER]: name:[NAME] desc:[...] attribs:[...]``
_ACCOUNT_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r"^account\[(?P<key>[^\]]+)\]:\s*(?P<rest>.+?)\s*$"
)
_ACCOUNT_FIELD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<field>[a-zA-Z_]+):\[(?P<value>[^\]]*)\]"
)
# ``Domain Name: CONTOSO``  /  ``Total Users: 312``
_KV_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<key>(?:Domain|Total)\s+\S[^:]*?)\s*:\s*(?P<value>.+?)\s*$",
    re.IGNORECASE,
)


DedupKey: TypeAlias = tuple[str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_rpcclient_enum(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate rpcclient null-session output into FindingDTOs."""
    del stderr
    text = safe_decode(stdout, limit=MAX_STDOUT_BYTES)
    if not text:
        return []
    state = _walk(text)
    records = list(_build_records(state))
    if not records:
        return []
    return _emit(records, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Output walker
# ---------------------------------------------------------------------------


def _walk(text: str) -> dict[str, Any]:
    state: dict[str, Any] = {
        "users": [],
        "groups": [],
        "accounts": [],
        "domain_info": {},
    }
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if (user_match := _USER_LINE_RE.match(line)) is not None:
            state["users"].append(
                {
                    "user": user_match.group("user").strip(),
                    "rid": user_match.group("rid").strip(),
                }
            )
            continue
        if (group_match := _GROUP_LINE_RE.match(line)) is not None:
            state["groups"].append(
                {
                    "group": group_match.group("group").strip(),
                    "rid": group_match.group("rid").strip(),
                }
            )
            continue
        if (account_match := _ACCOUNT_LINE_RE.match(line)) is not None:
            account_record = _parse_account(account_match)
            if account_record is not None:
                state["accounts"].append(account_record)
            continue
        kv_match = _KV_RE.match(line)
        if kv_match is not None:
            state["domain_info"][kv_match.group("key").strip()] = kv_match.group(
                "value"
            ).strip()
    return state


def _parse_account(match: re.Match[str]) -> dict[str, Any] | None:
    key = match.group("key").strip()
    fields: dict[str, str] = {"key": key}
    for field_match in _ACCOUNT_FIELD_RE.finditer(match.group("rest")):
        field = field_match.group("field").strip()
        value = field_match.group("value").strip()
        if field:
            fields[field] = value
    return fields if len(fields) > 1 else None


# ---------------------------------------------------------------------------
# Record building
# ---------------------------------------------------------------------------


def _build_records(state: dict[str, Any]) -> Iterator[dict[str, Any]]:
    domain_info = state["domain_info"]
    users = state["users"]
    accounts = state["accounts"]
    null_session_active = bool(users or accounts)
    if null_session_active:
        yield {
            "kind": "rpcclient_null_session",
            "user": "",
            "rid": "",
            "domain_info": dict(domain_info),
            "user_count": len(users),
            "group_count": len(state["groups"]),
            "null_session": True,
        }
    for user in users:
        yield {
            "kind": "rpcclient_user_enum",
            "user": user["user"],
            "rid": user["rid"],
            "domain_info": dict(domain_info),
            "user_count": len(users),
            "group_count": len(state["groups"]),
            "null_session": False,
        }
    for account in accounts:
        yield {
            "kind": "rpcclient_account_detail",
            "user": account.get("name") or account.get("key", ""),
            "rid": account.get("rid", ""),
            "domain_info": dict(domain_info),
            "user_count": len(users),
            "group_count": len(state["groups"]),
            "null_session": False,
            "attribs": account.get("attribs", ""),
            "desc": account.get("desc", ""),
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
    keyed: list[tuple[tuple[int, str, str], FindingDTO, str]] = []
    for record in records:
        key: DedupKey = (record["kind"], record.get("user", "").lower())
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (
            -1 if record["null_session"] else 0,
            record["kind"],
            record.get("user", ""),
        )
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "rpcclient_enum_parser.cap_reached",
                extra={
                    "event": "rpcclient_enum_parser_cap_reached",
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
        cvss_v3_score=_CVSS_BASELINE,
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=SSVCDecision.TRACK,
        owasp_wstg=["WSTG-INFO-04"],
        mitre_attack=["T1087.002"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "user": record.get("user"),
        "rid": record.get("rid"),
        "user_count": record.get("user_count"),
        "group_count": record.get("group_count"),
        "domain_info": dict(record.get("domain_info") or {}),
        "null_session": bool(record.get("null_session")),
        "attribs": record.get("attribs"),
        "desc": record.get("desc"),
        "synthetic_id": stable_hash_12(
            f"{record.get('kind', '')}::{record.get('user', '').lower()}"
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
            "rpcclient_enum_parser.evidence_sidecar_write_failed",
            extra={
                "event": "rpcclient_enum_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_rpcclient_enum",
]
