"""Parser for ``ldapsearch`` LDIF output (Backlog/dev1_md §4.17 — ARG-022).

OpenLDAP's ``ldapsearch -x -H ldap://<host> -b <basedn> -s sub`` emits
LDIF (RFC 2849) blocks separated by blank lines::

    # extended LDIF
    #
    # LDAPv3
    # base <DC=contoso,DC=local> with scope subtree
    # filter: (objectclass=*)
    # requesting: ALL
    #

    dn: CN=Administrator,CN=Users,DC=contoso,DC=local
    objectClass: top
    objectClass: person
    objectClass: organizationalPerson
    objectClass: user
    cn: Administrator
    sn: Administrator
    memberOf: CN=Domain Admins,CN=Users,DC=contoso,DC=local
    sAMAccountName: Administrator

    dn: CN=svc-backup,OU=Service Accounts,DC=contoso,DC=local
    ...

The parser produces one :class:`FindingDTO` per ``dn:`` block.  Severity
is rule-derived:

* High-value group membership (``Domain Admins`` / ``Enterprise
  Admins`` / ``Schema Admins``) → MEDIUM (CWE-269 + CWE-200).
* Anonymous bind worked AND data returned → LOW (CWE-200).
* Empty / pure-comment output → no findings (the parser stays silent
  rather than emitting a misleading INFO).

Sidecar
-------
``ldapsearch_findings.jsonl`` records the redacted DN attributes.  Any
hash-shaped attribute values (``unicodePwd``, ``ntPwdHistory``,
``lmPwdHistory``) are masked through :func:`redact_hash_string`.
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
    redact_hash_string,
    redact_hashes_in_evidence,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "ldapsearch_findings.jsonl"
_MAX_FINDINGS: Final[int] = 5_000
_MAX_VALUE_PER_ATTR: Final[int] = 256
_MAX_VALUES_PER_ATTR: Final[int] = 16


_PRIVILEGED_GROUPS: Final[frozenset[str]] = frozenset(
    {
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "domain controllers",
        "account operators",
        "backup operators",
        "server operators",
    }
)


_CVSS_PRIVILEGED_DISCLOSURE: Final[float] = 5.3
_CVSS_INFO_DISCLOSURE: Final[float] = 3.7


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------


_LDIF_ATTR_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<attr>[A-Za-z][A-Za-z0-9-]*):(?P<encoded>[:<]?)\s*(?P<value>.*?)\s*$"
)


DedupKey: TypeAlias = tuple[str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_ldapsearch(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate ldapsearch LDIF output into AUTH / INFO FindingDTOs."""
    del stderr
    text = safe_decode(stdout, limit=MAX_STDOUT_BYTES)
    if not text:
        return []
    blocks = list(_iter_blocks(text))
    if not blocks:
        return []
    return _emit(blocks, artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# LDIF block iteration
# ---------------------------------------------------------------------------


def _iter_blocks(text: str) -> Iterator[dict[str, Any]]:
    """Yield one normalised dict per LDIF entry."""
    current: dict[str, list[str]] = {}
    last_attr: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            block = _finalise_block(current)
            if block is not None:
                yield block
            current = {}
            last_attr = None
            continue
        if line.startswith("#"):
            continue
        if line.startswith((" ", "\t")) and last_attr is not None:
            current[last_attr][-1] += line.strip()
            continue
        attr_match = _LDIF_ATTR_RE.match(line)
        if attr_match is None:
            continue
        attr = attr_match.group("attr").strip()
        if not attr:
            continue
        value = attr_match.group("value").strip()
        current.setdefault(attr, []).append(value)
        last_attr = attr
    block = _finalise_block(current)
    if block is not None:
        yield block


def _finalise_block(current: dict[str, list[str]]) -> dict[str, Any] | None:
    """Return a normalised dict for an LDIF block keyed on ``dn``."""
    if not current:
        return None
    dn_values = current.get("dn") or current.get("DN")
    if not dn_values:
        return None
    dn = dn_values[0].strip()
    if not dn:
        return None
    object_classes = sorted(
        {value.strip().lower() for value in current.get("objectClass") or []}
    )
    member_of = [value.strip() for value in current.get("memberOf") or []][
        :_MAX_VALUES_PER_ATTR
    ]
    privileged = _is_privileged(member_of)
    raw_attrs = {
        key: [value[:_MAX_VALUE_PER_ATTR] for value in values][:_MAX_VALUES_PER_ATTR]
        for key, values in current.items()
        if key not in {"dn", "DN"}
    }
    return {
        "kind": "ldap_privileged_principal" if privileged else "ldap_principal",
        "dn": dn,
        "object_classes": object_classes,
        "member_of": member_of,
        "attributes": raw_attrs,
        "privileged": privileged,
    }


def _is_privileged(member_of: list[str]) -> bool:
    for dn in member_of:
        cn_match = re.search(r"CN=([^,]+)", dn, re.IGNORECASE)
        if cn_match is None:
            continue
        if cn_match.group(1).strip().lower() in _PRIVILEGED_GROUPS:
            return True
    return False


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
        key: DedupKey = (record["kind"], record["dn"].lower())
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record)
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        sort_key = (-1 if record["privileged"] else 0, record["dn"].lower())
        keyed.append((sort_key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "ldapsearch_parser.cap_reached",
                extra={
                    "event": "ldapsearch_parser_cap_reached",
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
    if record.get("privileged"):
        return make_finding_dto(
            category=FindingCategory.AUTH,
            cwe=[269, 200, 287],
            cvss_v3_vector=SENTINEL_CVSS_VECTOR,
            cvss_v3_score=_CVSS_PRIVILEGED_DISCLOSURE,
            confidence=ConfidenceLevel.CONFIRMED,
            ssvc_decision=SSVCDecision.ATTEND,
            owasp_wstg=["WSTG-INFO-05", "WSTG-ATHN-04"],
            mitre_attack=["T1087.002", "T1069.002"],
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_CVSS_INFO_DISCLOSURE,
        confidence=ConfidenceLevel.LIKELY,
        ssvc_decision=SSVCDecision.TRACK,
        owasp_wstg=["WSTG-INFO-05"],
        mitre_attack=["T1087.002"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    redacted_attrs: dict[str, list[str]] = {}
    for attr, values in (record.get("attributes") or {}).items():
        redacted_attrs[attr] = [
            redact_hash_string(value) if isinstance(value, str) else value
            for value in values
        ]
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "dn": record.get("dn"),
        "object_classes": list(record.get("object_classes") or []),
        "member_of": list(record.get("member_of") or []),
        "privileged": bool(record.get("privileged")),
        "attributes": redacted_attrs,
        "synthetic_id": stable_hash_12(
            f"{record.get('dn', '')}::{int(bool(record.get('privileged')))}"
        ),
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value in (None, "", [], {}) and key != "privileged":
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
            "ldapsearch_parser.evidence_sidecar_write_failed",
            extra={
                "event": "ldapsearch_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_ldapsearch",
]
