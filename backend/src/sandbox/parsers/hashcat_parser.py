"""Parser for ``hashcat`` cracked-output (ARG-032 batch 4c).

Hashcat writes cracked credentials to ``--outfile /out/cracked.txt``.
Canonical line shape (``--outfile-format 2``)::

    <hash>:<plain>

For brevity hashcat 6+ defaults to format 2; format 3 prepends ``<salt>``
making the line ``<hash>:<salt>:<plain>``.  Both shapes are recognised
and **both** the hash and the cleartext plain are masked before any
finding is emitted.

CRITICAL security gates
-----------------------

* Hash bytes are replaced with the canonical
  :data:`src.sandbox.parsers._text_base.REDACTED_HASH_MARKER`.
* The cracked plaintext is replaced with
  :data:`src.sandbox.parsers._text_base.REDACTED_PASSWORD_MARKER` plus
  a length hint (so an operator sees how long the password was without
  ever seeing the value).
"""

from __future__ import annotations

import json
import logging
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
    REDACTED_HASH_MARKER,
    REDACTED_PASSWORD_MARKER,
    load_canonical_or_stdout_text,
    redact_hashes_in_evidence,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "hashcat_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = (
    "cracked.txt",
    "hashcat.potfile",
    "hashcat.txt",
)
_MAX_FINDINGS: Final[int] = 5_000


_DedupKey: TypeAlias = tuple[str, str]


def parse_hashcat(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate hashcat cracked-output lines into AUTH FindingDTOs."""
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
        key: _DedupKey = (record["hash_kind"], record["hash_fingerprint"])
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding()
        evidence = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "hashcat.cap_reached",
                extra={
                    "event": "hashcat_cap_reached",
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
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\r\n")
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":", 2)
        if len(parts) < 2:
            continue
        if len(parts) == 2:
            hash_token, plain = parts
            salt = ""
        else:
            hash_token, salt, plain = parts
        hash_token = hash_token.strip()
        if not hash_token:
            continue
        kind = _classify_hash(hash_token)
        yield {
            "hash_kind": kind,
            "hash_fingerprint": stable_hash_12(hash_token),
            "salt_present": "true" if salt else "false",
            "plain_length": str(len(plain)),
        }


def _classify_hash(token: str) -> str:
    """Assign a coarse-grained hash family label.

    The classifier purposely returns a *family* label (``ntlm`` /
    ``sha256`` / ``bcrypt`` / ``raw``) rather than the exact hashcat
    mode number — the FindingDTO + sidecar should not surface
    fine-grained crypto metadata that a recipient could weaponise.
    """
    stripped = token.strip()
    lowered = stripped.lower()
    hex_only = all(c in "0123456789abcdef" for c in lowered)
    if stripped.startswith("$2"):
        return "bcrypt"
    if stripped.startswith("$argon2"):
        return "argon2"
    if stripped.startswith("$krb5"):
        return "kerberos_blob"
    if stripped.startswith("$DCC2$"):
        return "dcc2"
    if stripped.startswith("$NT$") or (hex_only and len(lowered) == 32):
        return "ntlm"
    if hex_only and len(lowered) == 40:
        return "sha1"
    if hex_only and len(lowered) == 64:
        return "sha256"
    return "raw"


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.AUTH,
        cwe=[916, 521, 798],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=7.5,
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=SSVCDecision.ACT,
        owasp_wstg=["WSTG-ATHN-07", "WSTG-CRYP-04"],
        mitre_attack=["T1110.002"],
    )


def _build_evidence(record: dict[str, str], *, tool_id: str) -> str:
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "hash_kind": record["hash_kind"],
        "hash_fingerprint": record["hash_fingerprint"],
        "salt_present": record["salt_present"],
        "plain_length": int(record["plain_length"]),
        "hash_value": REDACTED_HASH_MARKER,
        "plain_value": REDACTED_PASSWORD_MARKER,
    }
    cleaned = redact_hashes_in_evidence(
        {k: str(v) for k, v in payload.items() if isinstance(v, str)}
    )
    payload.update(cleaned)
    return json.dumps(payload, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_hashcat",
]
