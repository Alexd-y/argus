"""Parser for ``responder`` LLMNR/NBT-NS poisoning log (ARG-032 batch 4c).

Responder writes captured authentications to its session log
(``-Lf /out/responder.log``).  Canonical line shapes for captured
NTLMv2 / NTLMv1 / SMB challenges::

    [SMB] NTLMv2-SSP Client   : 10.0.0.10
    [SMB] NTLMv2-SSP Username : CORP\\bob
    [SMB] NTLMv2-SSP Hash     : bob::CORP:1122334455667788:ABCDEF...:0101000000000000...
    [HTTP] NTLMv1 Hash        : alice::CORP:0011223344556677:ABC...AB:1234...

CRITICAL security gate
----------------------

This parser is the **only** place in the catalog that legitimately sees
captured NTLM hashes from on-the-wire poisoning.  Per the ARG-032
acceptance criteria the entire hash blob is masked **before** the
FindingDTO is built, so the raw bytes never traverse the Pydantic
validator and never appear in the sidecar.  Only the protocol, NTLM
version, domain, username, and a synthetic fingerprint survive.
"""

from __future__ import annotations

import json
import logging
import re
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
    REDACTED_NT_HASH_MARKER,
    load_canonical_or_stdout_text,
    redact_hashes_in_evidence,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "responder_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("responder.log", "responder.txt")
_MAX_FINDINGS: Final[int] = 1_000

# Header line that opens a captured-auth block:
#   ``[SMB] NTLMv2-SSP Client : <ip>``
_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"^\[(?P<proto>[A-Z0-9]+)\]\s+"
    r"(?P<ntlm>NTLMv1|NTLMv2)(?:-SSP)?"
    r"\s+(?P<key>Client|Username|Hash)\s*:\s*"
    r"(?P<value>.+?)\s*$",
)
_USER_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?P<domain>[^\\:\s]+)\\)?(?P<user>[^\\:\s]+)$"
)


_DedupKey: TypeAlias = tuple[str, str, str, str, str]


def parse_responder(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate responder log lines into hash-redacted AUTH FindingDTOs."""
    del stderr
    text = load_canonical_or_stdout_text(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_names=_CANONICAL_NAMES,
        tool_id=tool_id,
    )
    if not text:
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for record in _iter_records(text):
        key: _DedupKey = (
            record["proto"],
            record["ntlm_version"],
            record["client_ip"],
            record["domain"],
            record["username"],
        )
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding()
        evidence = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "responder.cap_reached",
                extra={
                    "event": "responder_cap_reached",
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


def _iter_records(text: str) -> Iterator[dict[str, str]]:
    """Yield one normalised record per ``Hash :`` line.

    Responder writes a multi-line block per capture (Client → Username
    → Hash).  We track the in-progress block with a small state dict and
    flush it on the ``Hash`` line.
    """
    block: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _HEADER_RE.match(line)
        if match is None:
            continue
        proto = match.group("proto").upper()
        ntlm = match.group("ntlm")
        key = match.group("key")
        value = match.group("value").strip()
        block_key = f"{proto}|{ntlm}"
        if block.get("_key") != block_key:
            block = {"_key": block_key, "proto": proto, "ntlm_version": ntlm}
        if key == "Client":
            block["client_ip"] = value
        elif key == "Username":
            user_match = _USER_RE.match(value)
            if user_match:
                block["domain"] = (user_match.group("domain") or "").strip()
                block["username"] = user_match.group("user").strip()
            else:
                block["domain"] = ""
                block["username"] = value
        elif key == "Hash":
            block.setdefault("client_ip", "")
            block.setdefault("domain", "")
            block.setdefault("username", "")
            yield {
                "proto": block["proto"],
                "ntlm_version": block["ntlm_version"],
                "client_ip": block["client_ip"],
                "domain": block["domain"],
                "username": block["username"],
            }
            block = {}


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.AUTH,
        cwe=[290, 522, 256, 200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=8.8,
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=SSVCDecision.ACT,
        owasp_wstg=["WSTG-ATHN-04", "WSTG-ATHN-06", "WSTG-INFO-08"],
        mitre_attack=["T1557.001", "T1187"],
    )


def _build_evidence(record: dict[str, str], *, tool_id: str) -> str:
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "proto": record["proto"],
        "ntlm_version": record["ntlm_version"],
        "client_ip": record["client_ip"],
        "domain": record["domain"],
        "username": record["username"],
        "ntlm_hash": REDACTED_NT_HASH_MARKER,
        "fingerprint_hash": stable_hash_12(
            f"responder|{record['proto']}|{record['ntlm_version']}|"
            f"{record['client_ip']}|{record['domain']}|{record['username']}"
        ),
    }
    cleaned = redact_hashes_in_evidence(
        {k: str(v) for k, v in payload.items() if isinstance(v, str)}
    )
    payload.update(cleaned)
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_responder",
]
