"""Parsers for the SNMP recon family (Backlog/dev1_md §4.12 / §4.17).

Two catalog tools emit line-based SNMP text that previously fell through
to the ARG-020 heartbeat:

* ``onesixtyone`` — fast SNMP community-string scanner.  Each positive
  hit is a single line ``<ip> [<community>] <sysDescr>`` (the sysDescr
  tail is optional).  A responding agent proves the community string is
  valid; default strings (``public`` / ``private`` / ``manager``)
  escalate to MISCONFIG (CWE-521).
* ``snmp_check`` — ``snmp-check`` enumerator.  Its verbose report is
  key/value text under section headers.  A successful run means the
  SNMP tree is readable → information exposure (CWE-200); a default
  community escalates to MISCONFIG (CWE-521).

Both parsers are conservative: they only report facts the tool observed
(a responding agent, the enumerated system fields) and never invent a
CVE.  ``sysDescr`` / field values are truncated and scrubbed before
landing in the evidence sidecar.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Any, Final

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    SSVCDecision,
)
from src.sandbox.parsers._base import make_finding_dto, stable_hash_12
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)

EVIDENCE_SIDECAR_NAME: Final[str] = "snmp_probe_findings.jsonl"
_MAX_FINDINGS: Final[int] = 2_000
_MAX_VALUE_LEN: Final[int] = 400

_ONESIXTYONE_CANONICAL: Final[tuple[str, ...]] = ("onesixtyone.txt",)
_SNMP_CHECK_CANONICAL: Final[tuple[str, ...]] = ("snmp.txt", "snmp_check.txt")

# Community strings shipped as vendor defaults — a positive hit on any of
# these is a hard misconfiguration, not merely information exposure.
_DEFAULT_COMMUNITIES: Final[frozenset[str]] = frozenset(
    {"public", "private", "manager", "community", "admin", "cisco"}
)

# onesixtyone hit line: ``192.0.2.10 [public] Hardware: x86 ...``.
_ONESIXTYONE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<host>\S+)\s+\[(?P<community>[^\]]+)\]\s*(?P<descr>.*)$"
)

# snmp-check ``  Hostname                      : router`` field lines.
_SNMP_CHECK_FIELDS: Final[dict[str, str]] = {
    "Hostname": "hostname",
    "Description": "description",
    "Contact": "contact",
    "Location": "location",
    "System date": "system_date",
    "Uptime system": "uptime_system",
    "Uptime snmp": "uptime_snmp",
    "Domain": "domain",
    "Device type": "device_type",
    "Motd": "motd",
}
_SNMP_CHECK_FIELD_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*(?P<label>"
    + "|".join(re.escape(label) for label in _SNMP_CHECK_FIELDS)
    + r")\s*:\s*(?P<value>.+?)\s*$"
)
# ``[+] Try to connect to 192.0.2.10:161 using SNMPv1 and community 'public'``
_SNMP_CHECK_COMMUNITY_RE: Final[re.Pattern[str]] = re.compile(
    r"community\s+'(?P<community>[^']+)'", re.IGNORECASE
)

DedupKey = tuple[str, str]


# ---------------------------------------------------------------------------
# onesixtyone
# ---------------------------------------------------------------------------


def parse_onesixtyone(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate onesixtyone community-scan hits into findings."""
    del stderr
    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=_ONESIXTYONE_CANONICAL,
        tool_id=tool_id,
    )
    if not text.strip():
        return []

    seen: set[DedupKey] = set()
    keyed: list[tuple[DedupKey, FindingDTO, str]] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "Scanning", "Sending")):
            continue
        match = _ONESIXTYONE_RE.match(line)
        if match is None:
            continue
        host = match.group("host").strip()
        community = match.group("community").strip()
        if not host or not community:
            continue

        key: DedupKey = (host, community.lower())
        if key in seen:
            continue
        seen.add(key)

        is_default = community.lower() in _DEFAULT_COMMUNITIES
        descr = match.group("descr").strip()
        if is_default:
            finding = make_finding_dto(
                category=FindingCategory.MISCONFIG,
                cwe=[521, 200],
                cvss_v3_score=5.3,
                confidence=ConfidenceLevel.LIKELY,
                ssvc_decision=SSVCDecision.ATTEND,
                owasp_wstg=["WSTG-INFO-09", "WSTG-ATHN-02"],
            )
        else:
            finding = make_finding_dto(
                category=FindingCategory.INFO,
                cwe=[200],
                cvss_v3_score=0.0,
                confidence=ConfidenceLevel.SUSPECTED,
                owasp_wstg=["WSTG-INFO-09"],
            )
        evidence = {
            "tool_id": tool_id,
            "host": host,
            "community": community,
            "default_community": is_default,
            "sys_descr": _truncate(descr) if descr else None,
        }
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "snmp_probe_parser.cap_reached",
                extra={
                    "event": "snmp_probe_parser_cap_reached",
                    "tool_id": tool_id,
                    "cap": _MAX_FINDINGS,
                },
            )
            break

    return _finalise(keyed, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# snmp-check
# ---------------------------------------------------------------------------


def parse_snmp_check(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate an snmp-check enumeration report into one finding."""
    del stderr
    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=_SNMP_CHECK_CANONICAL,
        tool_id=tool_id,
    )
    if not text.strip():
        return []

    fields: dict[str, str] = {}
    for raw_line in text.splitlines():
        match = _SNMP_CHECK_FIELD_RE.match(raw_line)
        if match is None:
            continue
        label = match.group("label")
        value = match.group("value").strip()
        canonical_key = _SNMP_CHECK_FIELDS[label]
        if value and canonical_key not in fields:
            fields[canonical_key] = _truncate(value)

    if not fields:
        # No recognised system field — do not fabricate a finding from
        # unstructured text.
        return []

    community_match = _SNMP_CHECK_COMMUNITY_RE.search(text)
    community = community_match.group("community") if community_match else None
    is_default = bool(community and community.lower() in _DEFAULT_COMMUNITIES)

    if is_default:
        finding = make_finding_dto(
            category=FindingCategory.MISCONFIG,
            cwe=[521, 200],
            cvss_v3_score=5.3,
            confidence=ConfidenceLevel.LIKELY,
            ssvc_decision=SSVCDecision.ATTEND,
            owasp_wstg=["WSTG-INFO-09", "WSTG-ATHN-02"],
        )
    else:
        finding = make_finding_dto(
            category=FindingCategory.INFO,
            cwe=[200],
            cvss_v3_score=0.0,
            confidence=ConfidenceLevel.CONFIRMED,
            owasp_wstg=["WSTG-INFO-09"],
        )

    evidence: dict[str, Any] = {"tool_id": tool_id, **fields}
    if community:
        evidence["community"] = community
        evidence["default_community"] = is_default

    dedup_seed = fields.get("hostname") or fields.get("description") or "snmp_check"
    key: DedupKey = ("snmp_check", stable_hash_12(dedup_seed))
    keyed = [(key, finding, _serialise(evidence))]
    return _finalise(keyed, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _finalise(
    keyed: list[tuple[DedupKey, FindingDTO, str]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    keyed.sort(key=lambda item: item[0])
    if keyed:
        persist_jsonl_sidecar(
            artifacts_dir,
            sidecar_name=EVIDENCE_SIDECAR_NAME,
            evidence_records=[blob for _, _, blob in keyed],
            tool_id=tool_id,
        )
    return [finding for _, finding, _ in keyed]


def _serialise(evidence: dict[str, Any]) -> str:
    cleaned = {key: value for key, value in evidence.items() if value not in (None, "", [], {})}
    scrubbed = scrub_evidence_strings(cleaned)
    return json.dumps(scrubbed, sort_keys=True, ensure_ascii=False)


def _truncate(value: str) -> str:
    if len(value) <= _MAX_VALUE_LEN:
        return value
    return value[:_MAX_VALUE_LEN] + "[truncated]"


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_onesixtyone",
    "parse_snmp_check",
]
