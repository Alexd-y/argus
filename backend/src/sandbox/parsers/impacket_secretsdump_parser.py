"""Parser for ``impacket_secretsdump`` line output (Backlog/dev1_md §4.17 — ARG-022).

Impacket's ``secretsdump.py`` extracts authentication material from a
domain controller (NTDS.dit), local SAM hive, LSA secrets, and the
DPAPI cached-credentials store.  The wrapper invokes::

    secretsdump.py {domain}/{user}:{pass}@{dc} -outputfile {out_dir}/secrets

and the canonical output line for each principal is

.. code-block:: text

    DOMAIN\\user:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

Five colon-separated fields:

* ``DOMAIN\\user`` (or just ``user`` for local accounts)
* ``RID`` (Relative Identifier — integer)
* ``LMHash`` (32 hex)
* ``NTHash`` (32 hex)
* trailing ``:::`` literal

Plus three companion variants the parser also recognises:

* **NTDS UnicodePwd / aes** lines —
  ``user:aes256-cts-hmac-sha1-96:<64hex-key>``
* **LSA Kerberos lines** — ``$krb5tgs$23$*…$<hex>`` blobs.
* **MSCash2 (DCC2)** — ``DOMAIN\\user:$DCC2$10240#user#…``

CRITICAL — hash redaction
-------------------------

This is the **only** parser in the catalog that legitimately receives
domain credential material.  Per ARG-022 acceptance criteria every
``LMHash`` / ``NTHash`` / Kerberos blob / MSCash2 / SHA digest is
masked **before** the FindingDTO is constructed (so the Pydantic
validator never sees the cleartext) and **before** any sidecar write.

The redaction relies on
:func:`src.sandbox.parsers._text_base.redact_hash_string`, which masks:

* ``LM:NT`` pairs (32:32 hex) → ``[REDACTED-NT-HASH]``
* lone NT/LM hashes (32 hex) → ``[REDACTED-NT-HASH]``
* SHA-1 / SHA-256 / AES-key bytes (40 / 64 hex) → ``[REDACTED-HASH]``
* ``$krb5tgs$/$krb5asrep$/$krb5pa$`` blobs → ``[REDACTED-KRB-HASH]``

Severity / category mapping
---------------------------

Every record this parser emits is an authenticated credential disclosure
against a domain controller, so:

* :class:`FindingCategory` = ``AUTH``
* :class:`ConfidenceLevel` = ``CONFIRMED``
* :class:`SSVCDecision` = ``ACT``
* CWE = [522 (Insufficiently Protected Credentials), 256 (Plaintext
  Storage), 200 (Information Exposure)]
* CVSS v3.1 base score = 9.8 (catastrophic credential disclosure)
* OWASP WSTG = ``WSTG-ATHN-06`` + ``WSTG-INFO-08``
* MITRE ATT&CK = ``T1003.003`` (NTDS.dit OS Credential Dumping) +
  ``T1003.002`` (SAM)

Dedup
-----
Stable key derived from ``(domain, user, rid)``; collisions on the same
principal across multiple invocations therefore collapse to a single
finding.  Hashes themselves are never part of the dedup key (they are
redacted before record construction).
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
    REDACTED_KRB_HASH_MARKER,
    REDACTED_NT_HASH_MARKER,
    redact_hash_string,
    redact_hashes_in_evidence,
)

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


EVIDENCE_SIDECAR_NAME: Final[str] = "impacket_secretsdump_findings.jsonl"
_MAX_FINDINGS: Final[int] = 5_000
_CVSS_DOMAIN_CRED_DUMP: Final[float] = 9.8


# ---------------------------------------------------------------------------
# Compiled regexes
# ---------------------------------------------------------------------------


# Canonical NTDS dump line:
#   ``[DOMAIN\\]user:RID:LMHash:NTHash:::``
# Domain prefix is optional (local SAM accounts have no domain).
_NTDS_LINE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?P<domain>[^\\:\s]+)\\)?(?P<user>[^:\s]+):"
    r"(?P<rid>\d+):"
    r"(?P<lm>[a-fA-F0-9]{32}):"
    r"(?P<nt>[a-fA-F0-9]{32}):::\s*$"
)

# Kerberos AES / DES key lines:
#   ``DOMAIN\user:aes256-cts-hmac-sha1-96:<hex-key>``
_KERBEROS_KEY_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?P<domain>[^\\:\s]+)\\)?(?P<user>[^:\s]+):"
    r"(?P<algo>(?:aes(?:128|256)-cts-hmac-sha1-96|des-cbc-md5|"
    r"des-cbc-crc|rc4-hmac|arcfour-hmac)):"
    r"(?P<key>[a-fA-F0-9]{16,128})\s*$"
)

# Domain-cached credentials v2 (DCC2 / MSCache2):
#   ``DOMAIN\user:$DCC2$10240#user#<hex>``
_DCC2_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?P<domain>[^\\:\s]+)\\)?(?P<user>[^:\s]+):"
    r"(?P<blob>\$DCC2\$\d+#[^\s:#]+#[a-fA-F0-9]+)\s*$"
)

# LSA cleartext machine-account password / DPAPI master keys:
#   ``DOMAIN\user:plain_password_hex:<hex>``
_LSA_HEX_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:(?P<domain>[^\\:\s]+)\\)?(?P<user>[^:\s]+):"
    r"(?P<tag>plain_password_hex|aad3b435b51404eeaad3b435b51404ee_history0):"
    r"(?P<value>[a-fA-F0-9]+)\s*$"
)

# Kerberos pre-auth / TGT blobs surfaced by ``-just-dc`` runs:
#   ``$krb5tgs$23$*user$DOMAIN$service*$blob$blob``
_KRB5_RE: Final[re.Pattern[str]] = re.compile(
    r"^\$krb5(?:tgs|asrep|pa)\$.+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public type aliases
# ---------------------------------------------------------------------------


DedupKey: TypeAlias = tuple[str, str, str, str]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_impacket_secretsdump(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate impacket-secretsdump output into hash-redacted FindingDTOs."""
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


def _iter_records(text: str) -> Iterator[dict[str, str]]:
    """Yield one normalised record per recognised line.

    Each record is already redacted — raw NT / LM / Kerberos hashes are
    replaced by the canonical markers BEFORE leaving this function so a
    downstream programming bug cannot leak them through a forgotten
    sidecar.
    """
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", "//")):
            continue
        record = _classify(line)
        if record is not None:
            yield record


def _classify(line: str) -> dict[str, str] | None:
    """Match ``line`` against the known impacket output shapes.

    Returns ``None`` when the line is not recognised — e.g. impacket's
    progress banner ``[*] Dumping Domain Credentials (domain\\uid:rid:...)``
    or the ``[+] Done`` footer; both are intentionally skipped.
    """
    ntds = _NTDS_LINE_RE.match(line)
    if ntds is not None:
        return _ntds_record(ntds)
    kerberos = _KERBEROS_KEY_RE.match(line)
    if kerberos is not None:
        return _kerberos_record(kerberos)
    dcc2 = _DCC2_RE.match(line)
    if dcc2 is not None:
        return _dcc2_record(dcc2)
    lsa = _LSA_HEX_RE.match(line)
    if lsa is not None:
        return _lsa_record(lsa)
    if _KRB5_RE.match(line):
        return {
            "kind": "kerberos_ticket",
            "domain": "",
            "user": "",
            "rid": "",
            "evidence": REDACTED_KRB_HASH_MARKER,
            "algo": "krb5_blob",
        }
    return None


def _ntds_record(match: re.Match[str]) -> dict[str, str]:
    return {
        "kind": "ntds_hash_pair",
        "domain": (match.group("domain") or "").strip(),
        "user": match.group("user").strip(),
        "rid": match.group("rid"),
        "evidence": f"{REDACTED_NT_HASH_MARKER}:{REDACTED_NT_HASH_MARKER}",
        "algo": "lm_nt_pair",
    }


def _kerberos_record(match: re.Match[str]) -> dict[str, str]:
    return {
        "kind": "kerberos_key",
        "domain": (match.group("domain") or "").strip(),
        "user": match.group("user").strip(),
        "rid": "",
        "evidence": redact_hash_string(match.group("key")),
        "algo": match.group("algo"),
    }


def _dcc2_record(match: re.Match[str]) -> dict[str, str]:
    return {
        "kind": "domain_cached_creds_v2",
        "domain": (match.group("domain") or "").strip(),
        "user": match.group("user").strip(),
        "rid": "",
        "evidence": redact_hash_string(match.group("blob")),
        "algo": "dcc2",
    }


def _lsa_record(match: re.Match[str]) -> dict[str, str]:
    return {
        "kind": "lsa_secret",
        "domain": (match.group("domain") or "").strip(),
        "user": match.group("user").strip(),
        "rid": "",
        "evidence": redact_hash_string(match.group("value")),
        "algo": match.group("tag"),
    }


# ---------------------------------------------------------------------------
# Pipeline (dedup → sort → sidecar)
# ---------------------------------------------------------------------------


def _emit(
    records: list[dict[str, str]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    seen: set[DedupKey] = set()
    keyed: list[tuple[DedupKey, FindingDTO, str]] = []
    for record in records:
        key = _dedup_key(record)
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding()
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        keyed.append((key, finding, evidence_blob))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "impacket_secretsdump_parser.cap_reached",
                extra={
                    "event": "impacket_secretsdump_parser_cap_reached",
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


def _dedup_key(record: dict[str, str]) -> DedupKey:
    return (
        record.get("kind", ""),
        record.get("domain", ""),
        record.get("user", ""),
        record.get("rid", ""),
    )


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.AUTH,
        cwe=[522, 256, 200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=_CVSS_DOMAIN_CRED_DUMP,
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=SSVCDecision.ACT,
        owasp_wstg=["WSTG-ATHN-06", "WSTG-INFO-08"],
        mitre_attack=["T1003.003", "T1003.002"],
    )


def _build_evidence(record: dict[str, str], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": record.get("kind"),
        "domain": record.get("domain"),
        "user": record.get("user"),
        "rid": record.get("rid"),
        "algorithm": record.get("algo"),
        "credential_preview": record.get("evidence"),
        "synthetic_id": stable_hash_12(
            f"{record.get('kind', '')}::{record.get('domain', '')}::"
            f"{record.get('user', '')}::{record.get('rid', '')}"
        ),
    }
    cleaned = {k: v for k, v in payload.items() if v not in (None, "", [])}
    redacted = redact_hashes_in_evidence(
        {k: str(v) for k, v in cleaned.items() if isinstance(v, str)}
    )
    cleaned.update(redacted)
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
            "impacket_secretsdump_parser.evidence_sidecar_write_failed",
            extra={
                "event": "impacket_secretsdump_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_impacket_secretsdump",
]
