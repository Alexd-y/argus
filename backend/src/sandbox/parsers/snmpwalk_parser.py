"""Parser for ``snmpwalk`` MIB output (Backlog/dev1_md §4.17 — ARG-022).

Net-SNMP's ``snmpwalk -v 2c -c <community> <host>`` produces one
record per OID in the form::

    SNMPv2-MIB::sysDescr.0 = STRING: Linux router 5.10.0 #1 SMP x86_64
    SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.8072.3.2.10
    SNMPv2-MIB::sysContact.0 = STRING: admin@contoso.local
    SNMPv2-MIB::sysName.0 = STRING: edge-router-01
    SNMPv2-MIB::sysLocation.0 = STRING: rack 14, datacenter east
    IF-MIB::ifNumber.0 = INTEGER: 12

The parser surfaces:

* a single :class:`FindingCategory.INFO` finding per host capturing the
  full ``sys*`` block (description, contact, name, location, uptime,
  object-id);
* a :class:`FindingCategory.MISCONFIG` HIGH finding when the wrapper
  was invoked with a ``community = public/private/manager`` value
  AND the agent answered (i.e. recognised default community).

Severity ladder
---------------
* Default community accepted (``public``/``private``/``manager``) →
  HIGH (CWE-521 Weak Password Requirements / CWE-200) — the device is
  exposing operational metadata to anonymous internet traffic.
* All other walks → LOW (CWE-200 information disclosure).

Sidecar
-------
``snmpwalk_findings.jsonl`` records the redacted ``sys*`` payload.
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
from src.sandbox.parsers._text_base import (
    parse_kv_lines,
    redact_hashes_in_evidence,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "snmpwalk_findings.jsonl"
_MAX_FINDINGS: Final[int] = 100
_MAX_STRING_PER_FIELD: Final[int] = 512


_DEFAULT_COMMUNITIES: Final[frozenset[str]] = frozenset(
    {"public", "private", "manager", "admin", "community", "snmp"}
)


_CVSS_DEFAULT_COMMUNITY: Final[float] = 7.5
_CVSS_INFO_DISCLOSURE: Final[float] = 3.7


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------


# OID = TYPE: VALUE — TYPE may be STRING/INTEGER/OID/Counter32/Hex-STRING/etc.
_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<oid>[\w.:-]+)\s*=\s*(?P<type>[A-Za-z][\w-]*):\s*(?P<value>.*?)\s*$"
)
_COMMUNITY_HINT_RE: Final[re.Pattern[str]] = re.compile(
    r"community\s*[=:]\s*(?P<community>\S+)",
    re.IGNORECASE,
)


# Mapping of `sys*` short names → canonical key in the evidence record.
_SYS_FIELDS: Final[dict[str, str]] = {
    "sysdescr": "sys_descr",
    "sysobjectid": "sys_object_id",
    "sysuptime": "sys_uptime",
    "syscontact": "sys_contact",
    "sysname": "sys_name",
    "syslocation": "sys_location",
    "sysservices": "sys_services",
}


DedupKey: TypeAlias = tuple[str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_snmpwalk(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate snmpwalk OID output into INFO / MISCONFIG FindingDTOs."""
    text = safe_decode(stdout, limit=MAX_STDOUT_BYTES)
    text_err = safe_decode(stderr, limit=MAX_STDOUT_BYTES)
    combined = "\n".join(filter(None, (text, text_err)))
    if not combined:
        return []
    summary = _summarise(combined)
    if not summary["sys"] and not summary["interfaces"] and not summary["raw_oids"]:
        return []
    record = _build_record(summary)
    return _emit([record], artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Summarisation
# ---------------------------------------------------------------------------


def _summarise(text: str) -> dict[str, Any]:
    """Aggregate OID lines into a dense per-host dict."""
    summary: dict[str, Any] = {
        "sys": {},
        "interfaces": 0,
        "raw_oids": 0,
        "community_hint": "",
        "default_community": False,
    }
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        community_match = _COMMUNITY_HINT_RE.search(line)
        if community_match is not None:
            community = community_match.group("community").lower().strip()
            summary["community_hint"] = community
            if community in _DEFAULT_COMMUNITIES:
                summary["default_community"] = True
            continue
        match = _LINE_RE.match(line)
        if match is None:
            continue
        summary["raw_oids"] += 1
        oid = match.group("oid").strip()
        value = match.group("value").strip().strip('"')
        canonical = _canonical_key(oid)
        if canonical is not None:
            summary["sys"][canonical] = _truncate(value)
        if "ifNumber" in oid:
            try:
                summary["interfaces"] = int(value.split()[0])
            except (ValueError, IndexError):
                continue
    _detect_default_community_from_kv(text, summary)
    return summary


def _detect_default_community_from_kv(text: str, summary: dict[str, Any]) -> None:
    """Inspect ``key=community`` style hints (we honour both ``=`` and ``:``)."""
    for key, value in parse_kv_lines(text, sep=":"):
        if key.lower().endswith("community"):
            community = value.strip().lower()
            if community in _DEFAULT_COMMUNITIES:
                summary["community_hint"] = community
                summary["default_community"] = True


def _canonical_key(oid: str) -> str | None:
    lowered = oid.lower()
    for short, canonical in _SYS_FIELDS.items():
        if short in lowered:
            return canonical
    return None


def _truncate(value: str) -> str:
    if len(value) <= _MAX_STRING_PER_FIELD:
        return value
    return value[:_MAX_STRING_PER_FIELD] + "...[truncated]"


def _build_record(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "snmpwalk_default_community"
        if summary["default_community"]
        else "snmpwalk_info_disclosure",
        "default_community": bool(summary["default_community"]),
        "community_hint": summary["community_hint"],
        "interfaces": summary["interfaces"],
        "raw_oid_count": summary["raw_oids"],
        **summary["sys"],
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
        key: DedupKey = (
            record.get("kind", ""),
            record.get("sys_name") or record.get("sys_descr") or "",
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
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


def _build_finding(record: dict[str, Any]) -> FindingDTO:
    is_default = bool(record.get("default_community"))
    if is_default:
        return make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[521, 200],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=_CVSS_DEFAULT_COMMUNITY,
            confidence=ConfidenceLevel.CONFIRMED,
            ssvc_decision=SSVCDecision.ATTEND,
            owasp_wstg=["WSTG-INFO-09", "WSTG-CONF-05"],
            mitre_attack=["T1046", "T1110.001"],
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_CVSS_INFO_DISCLOSURE,
        confidence=ConfidenceLevel.LIKELY,
        ssvc_decision=SSVCDecision.TRACK,
        owasp_wstg=["WSTG-INFO-09"],
        mitre_attack=["T1046"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "default_community": bool(record.get("default_community")),
        "community_hint": record.get("community_hint"),
        "sys_descr": record.get("sys_descr"),
        "sys_contact": record.get("sys_contact"),
        "sys_name": record.get("sys_name"),
        "sys_location": record.get("sys_location"),
        "sys_object_id": record.get("sys_object_id"),
        "sys_uptime": record.get("sys_uptime"),
        "sys_services": record.get("sys_services"),
        "interface_count": record.get("interfaces"),
        "raw_oid_count": record.get("raw_oid_count"),
        "synthetic_id": stable_hash_12(
            f"{record.get('kind', '')}::{record.get('sys_name') or record.get('sys_descr') or ''}"
        ),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value in (None, "", 0, False) and key not in ("default_community",):
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
            "snmpwalk_parser.evidence_sidecar_write_failed",
            extra={
                "event": "snmpwalk_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


def _iter_oids(text: str) -> Iterator[tuple[str, str, str]]:
    """Public helper exposed for tests — yields (oid, type, value) per line."""
    for raw_line in text.splitlines():
        match = _LINE_RE.match(raw_line.strip())
        if match is not None:
            yield (
                match.group("oid").strip(),
                match.group("type").strip(),
                match.group("value").strip(),
            )


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_snmpwalk",
]
