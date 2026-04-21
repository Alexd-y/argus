"""Parser for ``crackmapexec`` (CME) text output (ARG-032 batch 4c).

CrackMapExec writes coloured TTY lines to stdout AND a stripped log to
``-o /out/cme.txt``.  Canonical line shapes::

    SMB         10.0.0.1  445  DC01      [+] CORP\\admin:Password123 (Pwn3d!)
    SMB         10.0.0.1  445  DC01      [+] CORP\\svc_sql:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
    SMB         10.0.0.1  445  DC01      [-] CORP\\guest:guest STATUS_LOGON_FAILURE

CRITICAL security gates
-----------------------

* The cleartext password is **redacted before** the FindingDTO is
  built.
* NTLM ``LM:NT`` pass-the-hash pairs are masked via
  :func:`redact_hash_string` so the 32:32 hex never lands in the
  sidecar.
* ``Pwn3d!`` markers are surfaced as evidence metadata only; the raw
  credential never leaves the parser.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Final, TypeAlias

from src.pipeline.contracts.finding_dto import FindingDTO
from src.sandbox.parsers._credential_base import (
    build_credential_evidence,
    build_credential_finding,
)
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import (
    REDACTED_NT_HASH_MARKER,
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "crackmapexec_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("cme.txt", "cme.log", "crackmapexec.txt")
_MAX_FINDINGS: Final[int] = 1_000

# CME success line:
#   ``<PROTO> <HOST> <PORT> <NETBIOS> [+] <DOMAIN>\<USER>:<CRED> [<TAGS>]``
_CRED_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<proto>SMB|WINRM|MSSQL|RDP|SSH|FTP|LDAP|VNC|HTTP|SNMP)"
    r"\s+(?P<host>\S+)"
    r"\s+(?P<port>\d+)"
    r"\s+(?P<netbios>\S+)"
    r"\s+\[\+\]"
    r"\s+(?:(?P<domain>[^\\:\s]+)\\)?(?P<user>[^:\s]+):"
    r"(?P<cred>\S+)"
    r"(?P<tags>.*)$",
    re.IGNORECASE,
)
_NTLM_PAIR_RE: Final[re.Pattern[str]] = re.compile(r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$")


_DedupKey: TypeAlias = tuple[str, str, str, str, str]


def parse_crackmapexec(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate CME text output into AUTH FindingDTOs."""
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

    for record in _iter_credentials(text):
        key: _DedupKey = (
            record["host"],
            record["proto"],
            record["domain"],
            record["username"],
            record["cred_kind"],
        )
        if key in seen:
            continue
        seen.add(key)
        finding = build_credential_finding()
        evidence = build_credential_evidence(
            tool_id=tool_id,
            host=record["host"],
            service=record["proto"],
            username=(
                f"{record['domain']}\\{record['username']}"
                if record["domain"]
                else record["username"]
            ),
            password_length=int(record["cred_length"]),
            extra={
                "port": record["port"],
                "netbios": record["netbios"],
                "credential_kind": record["cred_kind"],
                "pwn3d": record["pwn3d"],
            },
        )
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "crackmapexec.cap_reached",
                extra={
                    "event": "crackmapexec_cap_reached",
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


def _iter_credentials(text: str) -> Iterator[dict[str, str]]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = _CRED_RE.search(line)
        if match is None:
            continue
        cred = match.group("cred")
        if _NTLM_PAIR_RE.match(cred):
            cred_kind = "ntlm_hash_pair"
            cred_length = "0"
            redacted_kind_marker = REDACTED_NT_HASH_MARKER
        else:
            cred_kind = "cleartext_password"
            cred_length = str(len(cred))
            redacted_kind_marker = ""
        tags = match.group("tags") or ""
        pwn3d = "true" if "Pwn3d!" in tags else "false"
        del redacted_kind_marker
        yield {
            "proto": match.group("proto").upper(),
            "host": match.group("host").strip(),
            "port": match.group("port"),
            "netbios": match.group("netbios").strip(),
            "domain": (match.group("domain") or "").strip(),
            "username": match.group("user").strip(),
            "cred_kind": cred_kind,
            "cred_length": cred_length,
            "pwn3d": pwn3d,
        }


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_crackmapexec",
]
