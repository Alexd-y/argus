"""Shared text-line helpers for ARG-022 / ARG-032 TEXT_LINES parsers.

ARG-022 wires the §4.2 + §4.12 + §4.17 batch of Active Directory / SMB /
SNMP / LDAP tools whose output is line-based plain text (no JSON
envelope).  The ten parsers (``impacket_secretsdump``, ``evil_winrm``,
``kerbrute``, ``bloodhound_python``, ``snmpwalk``, ``ldapsearch``,
``smbclient_check``, ``smbmap``, ``enum4linux_ng``, ``rpcclient_enum``)
all share three primitives:

* a ``key = value`` / ``key: value`` line tokeniser;
* a regex sweep that returns named ``(pattern_name, match)`` tuples;
* a hash-redaction pass that strips NT / LM / SHA fingerprints from any
  evidence dict before the sidecar is persisted.

ARG-032 (Cycle 4) extends the toolbox with two redaction primitives the
auth / browser / binary parser families share:

* :func:`redact_password_in_text` — masks ``password=…`` /
  ``passwd: …`` / ``Password: …`` / URL ``://user:pass@…`` patterns.
  Used by the credential-bruteforce family
  (``hydra`` / ``medusa`` / ``patator`` / ``ncrack`` / ``crackmapexec``)
  whose output contains cleartext credentials by design.
* :func:`redact_memory_address` — masks any ``0x[0-9a-fA-F]{8,}``
  address.  Used by the binary-analysis family
  (``radare2_info`` / ``apktool`` / ``binwalk`` / ``jadx``) so ASLR
  offsets do not leak into FindingDTO fields.

Every helper here is **pure** — no I/O, no global state, no logging
side-effect — so each per-tool parser can compose them freely without
worrying about leak channels.

Hash redaction (security gate)
------------------------------
The text-output ARG-022 family is the first parser cluster that
legitimately sees credential material in the wild (NTDS.dit dumps,
Kerberos pre-auth hashes, SAM blobs).  :func:`redact_hashes_in_evidence`
folds the policy into a single chokepoint:

* exact ``LM:NT`` pairs ``[a-f0-9]{32}:[a-f0-9]{32}`` → ``[REDACTED-NT-HASH]``;
* lone NT/LM hashes (``[a-f0-9]{32}``) → ``[REDACTED-NT-HASH]``;
* SHA-1 (``[a-f0-9]{40}``) and SHA-256 (``[a-f0-9]{64}``) bare hex →
  ``[REDACTED-HASH]`` (catches Kerberos AES keys + Kerberoast outputs);
* Kerberos ``$krb5tgs$``/``$krb5asrep$`` blobs → ``[REDACTED-KRB-HASH]``.

The function operates on values already coerced into ``str`` and never
attempts to interpret bytes — that is the parser's responsibility.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Final

from src.sandbox.parsers._base import MAX_STDOUT_BYTES, safe_decode

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public constants
# ---------------------------------------------------------------------------


REDACTED_NT_HASH_MARKER: Final[str] = "[REDACTED-NT-HASH]"
REDACTED_HASH_MARKER: Final[str] = "[REDACTED-HASH]"
REDACTED_KRB_HASH_MARKER: Final[str] = "[REDACTED-KRB-HASH]"
REDACTED_PASSWORD_MARKER: Final[str] = "[REDACTED-PASSWORD]"
REDACTED_ADDRESS_MARKER: Final[str] = "[REDACTED-ADDR]"
REDACTED_COOKIE_MARKER: Final[str] = "[REDACTED-COOKIE]"
REDACTED_BEARER_MARKER: Final[str] = "[REDACTED-BEARER]"


# ---------------------------------------------------------------------------
# Regex catalogue — compiled once, reused per parser
# ---------------------------------------------------------------------------


# Order matters: longer / more specific patterns must match first so
# ``redact_hashes_in_evidence`` does not cut a 64-hex SHA-256 mid-string
# and leave a residual 32-hex / 40-hex hash visible.
_LM_NT_PAIR_RE: Final[re.Pattern[str]] = re.compile(
    r"\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b"
)
_KRB_BLOB_RE: Final[re.Pattern[str]] = re.compile(
    r"\$krb5(?:tgs|asrep|pa)\$[^\s\"]+",
    re.IGNORECASE,
)
_SHA256_RE: Final[re.Pattern[str]] = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE: Final[re.Pattern[str]] = re.compile(r"\b[a-fA-F0-9]{40}\b")
_NT_HASH_RE: Final[re.Pattern[str]] = re.compile(r"\b[a-fA-F0-9]{32}\b")


# ARG-032 — credential / address / header redactors.
#
# ``_PASSWORD_RE`` matches every common cleartext-password idiom emitted
# by Hydra, Medusa, Patator, Ncrack, CME, and friends:
#   * ``password=hunter2`` / ``passwd: hunter2`` / ``Password: hunter2``
#   * Hydra-style ``login: bob password: hunter2`` (``password\s+VALUE``)
#   * Medusa-style ``Pass: hunter2``
# The pattern also catches inline URL credentials (``://user:pw@host``).
_PASSWORD_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<key>"
    r"(?:^|[\s,;])(?:password|passwd|pwd|pass)"
    r"\s*[=:]\s*"
    r"|"
    r"(?:^|[\s,;])(?:password|passwd|pwd|pass)"
    r"\s+"
    r")"
    r"(?P<value>\"[^\"\s]+?\"|'[^'\s]+?'|[^\s,;]+)",
    re.IGNORECASE,
)
# URL credentials live in a separate pattern so the host part is preserved.
_URL_CREDS_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<scheme>(?:https?|ftps?|sftp|ssh|smb|ldaps?|mongodb|redis|mysql|postgres(?:ql)?|mssql)://)"
    r"(?P<user>[^:@/\s]+):"
    r"(?P<pwd>[^@/\s]+)"
    r"@",
    re.IGNORECASE,
)
# Hex memory addresses (8+ hex digits prefixed by 0x).  Used by the
# binary parser family to strip ASLR offsets.
_ADDRESS_RE: Final[re.Pattern[str]] = re.compile(
    r"0x[0-9a-fA-F]{8,}",
)
# HTTP ``Cookie:`` and ``Set-Cookie:`` headers.  Used by browser parsers
# walking HAR files where the response/request headers can carry
# session tokens.
_COOKIE_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<key>(?:^|\b)(?:Cookie|Set-Cookie)\s*[:=]\s*)"
    r"(?P<value>[^\r\n]+)",
    re.IGNORECASE,
)
# HTTP ``Authorization:`` headers + bare ``Bearer <token>`` strings.
_AUTH_HEADER_RE: Final[re.Pattern[str]] = re.compile(
    r"(?P<key>(?:^|\b)Authorization\s*[:=]\s*)"
    r"(?P<value>[^\r\n]+)",
    re.IGNORECASE,
)
_BEARER_TOKEN_RE: Final[re.Pattern[str]] = re.compile(
    r"\bBearer\s+[A-Za-z0-9._\-]+",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public helpers — line tokenisation
# ---------------------------------------------------------------------------


def parse_kv_lines(text: str, sep: str = "=") -> Iterator[tuple[str, str]]:
    """Yield trimmed ``(key, value)`` pairs for every ``key<sep>value`` line.

    * Splits on the **first** occurrence of ``sep`` so a value like
      ``OID = STRING: foo = bar`` keeps the trailing ``= bar`` inside
      the value half (the snmpwalk / enum4linux text formats both rely
      on this).
    * Skips blank lines and lines without a separator silently — the
      caller already classified the line via a regex sweep.
    * Strips inline comments starting with ``#`` and trailing whitespace.
    * Both halves are stripped; an empty key after stripping is skipped.

    The function is **pure**: no logging, no I/O, deterministic ordering
    follows the input.
    """
    if not text or not sep:
        return
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line:
            continue
        if sep not in line:
            continue
        key, value = line.split(sep, 1)
        key = key.strip()
        if not key:
            continue
        yield key, value.strip()


def extract_regex_findings(
    text: str,
    patterns: dict[str, re.Pattern[str]],
) -> Iterator[tuple[str, re.Match[str]]]:
    """Yield ``(pattern_name, match)`` for every match across ``patterns``.

    * Iterates patterns in ``patterns`` insertion order so the per-parser
      severity ladder (``CRITICAL`` → ``HIGH`` → ``LOW``) is preserved by
      registration order — exactly mirrors the existing
      ``_PROTOCOL_MAP`` precedent in :mod:`interactsh_parser`.
    * One pattern can match multiple lines; each match yields its own
      tuple so the parser can dedup downstream.
    * Empty / ``None`` text yields nothing (no exception).

    Pure — :class:`re.Pattern.finditer` is the only call.
    """
    if not text:
        return
    for name, pattern in patterns.items():
        for match in pattern.finditer(text):
            yield name, match


# ---------------------------------------------------------------------------
# Public helpers — credential-hash redaction (security gate)
# ---------------------------------------------------------------------------


def redact_hash_string(value: str) -> str:
    """Return ``value`` with every NT/LM/SHA/Kerberos hash masked.

    Used by the per-parser evidence builders before any value lands in
    the sidecar JSONL.  The substitutions run **in priority order**
    (most-specific first) so longer fingerprints (SHA-256, Kerberos
    blobs, LM:NT pairs) are masked before a residual 32-hex NT hash
    pattern would match a substring.

    Empty / non-``str`` values are returned unchanged so a downstream
    ``json.dumps`` does not crash on a ``None`` field.
    """
    if not value or not isinstance(value, str):
        return value
    redacted = _KRB_BLOB_RE.sub(REDACTED_KRB_HASH_MARKER, value)
    redacted = _LM_NT_PAIR_RE.sub(REDACTED_NT_HASH_MARKER, redacted)
    redacted = _SHA256_RE.sub(REDACTED_HASH_MARKER, redacted)
    redacted = _SHA1_RE.sub(REDACTED_HASH_MARKER, redacted)
    redacted = _NT_HASH_RE.sub(REDACTED_NT_HASH_MARKER, redacted)
    return redacted


def redact_hashes_in_evidence(evidence: dict[str, str]) -> dict[str, str]:
    """Return a new dict whose string values had NT/LM/SHA hashes masked.

    Only ``str`` values are touched — list / int / nested-dict members
    pass through verbatim.  The dict is **never** mutated in place; a
    fresh ``{}`` is returned so the caller's original record (used for
    dedup keys, sort keys, etc.) is untouched.

    Use as the LAST step before serialising to the sidecar:

    .. code-block:: python

        clean = redact_hashes_in_evidence(record)
        sidecar.write(json.dumps(clean))
    """
    if not evidence:
        return {}
    return {
        key: redact_hash_string(value) if isinstance(value, str) else value
        for key, value in evidence.items()
    }


# ---------------------------------------------------------------------------
# Public helpers — credential / address / cookie redaction (ARG-032)
# ---------------------------------------------------------------------------


def redact_password_in_text(value: str) -> str:
    """Mask cleartext passwords in ``value``.

    Replaces every ``password=…`` / ``passwd: …`` / ``://user:pw@`` /
    ``Pass: …`` occurrence with the canonical
    :data:`REDACTED_PASSWORD_MARKER`.  The leading key (``password=``)
    is preserved so the operator can still see *what* was redacted.

    Empty / non-``str`` values are returned unchanged.
    """
    if not value or not isinstance(value, str):
        return value
    redacted = _URL_CREDS_RE.sub(
        lambda m: f"{m.group('scheme')}{m.group('user')}:{REDACTED_PASSWORD_MARKER}@",
        value,
    )
    redacted = _PASSWORD_RE.sub(
        lambda m: f"{m.group('key')}{REDACTED_PASSWORD_MARKER}",
        redacted,
    )
    return redacted


def redact_memory_address(value: str) -> str:
    """Mask ``0x[0-9a-fA-F]{8,}`` memory addresses in ``value``.

    Used by binary-analysis parsers (radare2, apktool, jadx, binwalk)
    so ASLR offsets do not leak into FindingDTO / sidecar payloads.
    """
    if not value or not isinstance(value, str):
        return value
    return _ADDRESS_RE.sub(REDACTED_ADDRESS_MARKER, value)


def redact_http_secrets(value: str) -> str:
    """Mask ``Cookie`` / ``Set-Cookie`` / ``Authorization`` / Bearer tokens.

    Browser parsers walk HAR files whose request/response headers can
    legitimately contain session cookies and bearer tokens.  This
    helper folds the policy into a single chokepoint so a parser can
    apply it once before persisting evidence.
    """
    if not value or not isinstance(value, str):
        return value
    redacted = _COOKIE_HEADER_RE.sub(
        lambda m: f"{m.group('key')}{REDACTED_COOKIE_MARKER}",
        value,
    )
    redacted = _AUTH_HEADER_RE.sub(
        lambda m: f"{m.group('key')}{REDACTED_BEARER_MARKER}",
        redacted,
    )
    redacted = _BEARER_TOKEN_RE.sub(REDACTED_BEARER_MARKER, redacted)
    return redacted


_DEFAULT_SCRUBBERS: Final[tuple[Callable[[str], str], ...]] = (
    redact_hash_string,
    redact_password_in_text,
    redact_memory_address,
    redact_http_secrets,
)


def scrub_evidence_strings(
    evidence: dict[str, object],
    *,
    scrubbers: Sequence[Callable[[str], str]] = _DEFAULT_SCRUBBERS,
) -> dict[str, object]:
    """Run every ``str`` value in ``evidence`` through ``scrubbers`` in order.

    Non-string values pass through untouched; the dict is never mutated
    in place.  Use as the LAST step before serialising to the sidecar
    so a single chokepoint guards every evidence path.
    """
    if not evidence:
        return {}
    cleaned: dict[str, object] = {}
    for key, raw in evidence.items():
        value: object = raw
        if isinstance(value, str):
            text: str = value
            for scrubber in scrubbers:
                text = scrubber(text)
            value = text
        cleaned[key] = value
    return cleaned


# ---------------------------------------------------------------------------
# Public helpers — canonical-or-stdout text loading (ARG-032)
# ---------------------------------------------------------------------------


def load_canonical_or_stdout_text(
    *,
    stdout: bytes,
    artifacts_dir: Path,
    canonical_names: tuple[str, ...],
    tool_id: str,
    limit: int = MAX_STDOUT_BYTES,
) -> str:
    """Resolve text from ``canonical_names`` (in order) or fall back to stdout.

    The catalog declares per-tool evidence artefacts (``/out/<name>.txt``);
    in production the wrapper writes the canonical file and ``stdout`` is
    often empty.  In tests we usually pass content via ``stdout`` only.
    This helper folds both paths into a single call so every TEXT_LINES
    parser stays declarative.

    Path-traversal in ``canonical_names`` is rejected silently — only
    plain basenames (no ``/``, ``\\``, ``..``) are looked up.  ``OSError``
    raised by the read is logged and swallowed (best-effort).
    """
    for name in canonical_names:
        if "/" in name or "\\" in name or ".." in name:
            continue
        candidate = artifacts_dir / name
        if not candidate.is_file():
            continue
        try:
            raw = candidate.read_bytes()
        except OSError as exc:
            _logger.warning(
                "parsers.text_base.canonical_read_failed",
                extra={
                    "event": "parsers_text_base_canonical_read_failed",
                    "tool_id": tool_id,
                    "canonical_name": name,
                    "error_type": type(exc).__name__,
                },
            )
            continue
        text = safe_decode(raw, limit=limit)
        if text:
            return text
    return safe_decode(stdout, limit=limit)


__all__ = [
    "REDACTED_ADDRESS_MARKER",
    "REDACTED_BEARER_MARKER",
    "REDACTED_COOKIE_MARKER",
    "REDACTED_HASH_MARKER",
    "REDACTED_KRB_HASH_MARKER",
    "REDACTED_NT_HASH_MARKER",
    "REDACTED_PASSWORD_MARKER",
    "extract_regex_findings",
    "load_canonical_or_stdout_text",
    "parse_kv_lines",
    "redact_hash_string",
    "redact_hashes_in_evidence",
    "redact_http_secrets",
    "redact_memory_address",
    "redact_password_in_text",
    "scrub_evidence_strings",
]
