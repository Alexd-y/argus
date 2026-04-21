"""Parser for ``ntlmrelayx.py`` log output (ARG-032 batch 4c).

Impacket's ``ntlmrelayx`` writes successful relay events to its session
log (``-of /out/relay.log``).  Canonical line shapes::

    [*] Authenticating against smb://10.0.0.50 as CORP/Bob SUCCEED
    [*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
    Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
    [*] Done dumping SAM hashes
    [*] HTTP server returned 401 to 10.0.0.10 - relay attempt
    [+] Username and password attempts saved to /tmp/ntlmrelayx.creds

CRITICAL security gate
----------------------

NTLM ``LM:NT`` hash pairs and SHA digests are stripped via
:func:`redact_hashes_in_evidence` **before** the FindingDTO is built;
neither the raw hash nor the related principal's password ever lands
in the sidecar.  Successful relay events surface as AUTH findings so
operators can pivot, but the captured credential material is masked.
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
    redact_password_in_text,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "ntlmrelayx_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("relay.log", "ntlmrelayx.log")
_MAX_FINDINGS: Final[int] = 1_000

# Successful relay line:
#   ``[*] Authenticating against <scheme>://<target> as <DOMAIN>/<user> SUCCEED``
_RELAY_OK_RE: Final[re.Pattern[str]] = re.compile(
    r"\[\*\]\s+Authenticating\s+against\s+"
    r"(?P<scheme>[a-zA-Z]+)://(?P<target>\S+)"
    r"\s+as\s+(?:(?P<domain>[^/\\:\s]+)[/\\])?(?P<user>[^\s]+)"
    r"\s+SUCCEED",
    re.IGNORECASE,
)
# NTDS / SAM dump line:
#   ``Administrator:500:LM:NT:::``
_NTDS_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<user>[^:\s]+):(?P<rid>\d+):"
    r"(?P<lm>[a-fA-F0-9]{32}):(?P<nt>[a-fA-F0-9]{32}):::\s*$"
)


_DedupKey: TypeAlias = tuple[str, str, str, str, str]


def parse_ntlmrelayx(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate ntlmrelayx log lines into hash-redacted AUTH FindingDTOs."""
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
            record["kind"],
            record["scheme"],
            record["target"],
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
                "ntlmrelayx.cap_reached",
                extra={
                    "event": "ntlmrelayx_cap_reached",
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
        line = raw_line.strip()
        if not line:
            continue
        relay = _RELAY_OK_RE.search(line)
        if relay is not None:
            yield {
                "kind": "relay_success",
                "scheme": relay.group("scheme").lower(),
                "target": relay.group("target").strip(),
                "domain": (relay.group("domain") or "").strip(),
                "username": relay.group("user").strip(),
                "rid": "",
            }
            continue
        ntds = _NTDS_RE.match(line)
        if ntds is not None:
            yield {
                "kind": "sam_hash_pair",
                "scheme": "smb",
                "target": "",
                "domain": "",
                "username": ntds.group("user").strip(),
                "rid": ntds.group("rid"),
            }


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.AUTH,
        cwe=[290, 287, 522, 256],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=9.0,
        confidence=ConfidenceLevel.CONFIRMED,
        ssvc_decision=SSVCDecision.ACT,
        owasp_wstg=["WSTG-ATHN-04", "WSTG-ATHN-06"],
        mitre_attack=["T1557.001", "T1003.002"],
    )


def _build_evidence(record: dict[str, str], *, tool_id: str) -> str:
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "kind": record["kind"],
        "scheme": record["scheme"],
        "target": redact_password_in_text(record["target"]),
        "domain": record["domain"],
        "username": record["username"],
        "rid": record["rid"],
        "credential_preview": REDACTED_NT_HASH_MARKER,
        "fingerprint_hash": stable_hash_12(
            f"ntlmrelayx|{record['kind']}|{record['scheme']}|"
            f"{record['target']}|{record['domain']}|{record['username']}"
        ),
    }
    cleaned = {k: v for k, v in payload.items() if v not in (None, "", [])}
    redacted = redact_hashes_in_evidence(
        {k: str(v) for k, v in cleaned.items() if isinstance(v, str)}
    )
    cleaned.update(redacted)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_ntlmrelayx",
]
