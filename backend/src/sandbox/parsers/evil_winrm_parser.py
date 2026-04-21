"""Parser for ``evil_winrm`` interactive shell logs (Backlog/dev1_md §4.12 — ARG-022).

``evil-winrm`` is an authenticated WinRM client used post-exploitation
to spawn an interactive PowerShell session.  The wrapper streams the
session through ``tee`` into ``{out_dir}/winrm.log`` so the parser
sees a transcript of the form::

    Evil-WinRM shell v3.5
    Info: Establishing connection to remote endpoint
    *Evil-WinRM* PS C:\\Users\\Administrator\\Documents> whoami
    domain\\administrator
    *Evil-WinRM* PS C:\\Users\\Administrator\\Documents> exit
    Info: Exiting with code 0

This parser is **post-exploitation observability** — not a vulnerability
finder.  It emits one INFO :class:`FindingDTO` per successful session
capturing:

* hostname / target derived from the connection banner (when present);
* exit code (``Exiting with code N`` line; defaults to ``-1`` when the
  log was truncated);
* the last *operator command* (the text right after the final
  ``*Evil-WinRM* PS …>`` prompt);
* a one-line preview of the closing output.

Severity is :class:`ConfidenceLevel.SUSPECTED` and CVSS is the
:data:`SENTINEL_CVSS_SCORE` (0.0) — the heartbeat-class entry tells
operators "post-ex shell completed; review transcript" without lifting
the scan's worst-severity bar.

Evidence
--------
``evil_winrm_findings.jsonl`` carries the redacted transcript metadata.
NT/LM hash hex strings that may have leaked into PowerShell output are
masked through :func:`redact_hash_string` before sidecar persistence.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Final

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
    SSVCDecision,
)
from src.sandbox.parsers._base import (
    MAX_STDOUT_BYTES,
    SENTINEL_CVSS_SCORE,
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


EVIDENCE_SIDECAR_NAME: Final[str] = "evil_winrm_findings.jsonl"
_MAX_FINDINGS: Final[int] = 100
_MAX_PREVIEW_CHARS: Final[int] = 256


# ---------------------------------------------------------------------------
# Regex catalogue
# ---------------------------------------------------------------------------


_BANNER_RE: Final[re.Pattern[str]] = re.compile(
    r"Establishing connection to remote endpoint(?::\s*(?P<host>\S+))?",
    re.IGNORECASE,
)
_PROMPT_RE: Final[re.Pattern[str]] = re.compile(
    r"^\*Evil-WinRM\*\s+PS\s+(?P<cwd>[^>]+)>\s*(?P<command>.*?)\s*$"
)
_EXIT_CODE_RE: Final[re.Pattern[str]] = re.compile(
    r"Exiting with code\s+(?P<code>-?\d+)",
    re.IGNORECASE,
)
_ERROR_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?:Error|FATAL|Exception)\s*:\s*(?P<msg>.+?)\s*$",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def parse_evil_winrm(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate evil-winrm transcript into one INFO post-ex marker."""
    del stderr
    text = safe_decode(stdout, limit=MAX_STDOUT_BYTES)
    if not text.strip():
        return []
    record = _summarise(text)
    if record is None:
        return []
    return _emit([record], artifacts_dir=artifacts_dir, tool_id=tool_id)


# ---------------------------------------------------------------------------
# Summarisation
# ---------------------------------------------------------------------------


def _summarise(text: str) -> dict[str, Any] | None:
    """Compress a full transcript into a single observability record."""
    host: str | None = None
    exit_code: int | None = None
    last_command: str | None = None
    last_cwd: str | None = None
    errors: list[str] = []
    for raw_line in _strip_invisible(text):
        if (banner_host := _match_banner(raw_line)) is not None:
            host = banner_host
            continue
        prompt = _PROMPT_RE.match(raw_line)
        if prompt is not None and prompt.group("command").strip():
            last_command = prompt.group("command").strip()
            last_cwd = prompt.group("cwd").strip()
            continue
        exit_match = _EXIT_CODE_RE.search(raw_line)
        if exit_match is not None:
            try:
                exit_code = int(exit_match.group("code"))
            except ValueError:
                exit_code = None
            continue
        error_match = _ERROR_RE.match(raw_line)
        if error_match is not None and len(errors) < 5:
            errors.append(error_match.group("msg"))
    if host is None and exit_code is None and last_command is None and not errors:
        return None
    return {
        "host": host or "",
        "exit_code": exit_code if exit_code is not None else -1,
        "last_command": _truncate(last_command or ""),
        "last_cwd": _truncate(last_cwd or ""),
        "errors": errors,
    }


def _strip_invisible(text: str) -> Iterator[str]:
    """Yield lines with ANSI / carriage-return artefacts removed."""
    for raw_line in text.splitlines():
        cleaned = _ANSI_RE.sub("", raw_line).replace("\r", "").rstrip()
        if cleaned:
            yield cleaned


_ANSI_RE: Final[re.Pattern[str]] = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _match_banner(line: str) -> str | None:
    match = _BANNER_RE.search(line)
    if match is None:
        return None
    return (match.group("host") or "").strip() or ""


def _truncate(value: str) -> str:
    if len(value) <= _MAX_PREVIEW_CHARS:
        return value
    return value[:_MAX_PREVIEW_CHARS] + "...[truncated]"


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------


def _emit(
    records: list[dict[str, Any]],
    *,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    keyed: list[tuple[str, FindingDTO, str]] = []
    for record in records:
        finding = _build_finding()
        evidence_blob = _build_evidence(record, tool_id=tool_id)
        key = stable_hash_12(
            f"{record.get('host', '')}::{record.get('exit_code')}::"
            f"{record.get('last_command', '')}"
        )
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


def _build_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[1059],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=SENTINEL_CVSS_SCORE,
        confidence=ConfidenceLevel.SUSPECTED,
        ssvc_decision=SSVCDecision.TRACK,
        owasp_wstg=["WSTG-ATHN-01"],
        mitre_attack=["T1059.001", "T1021.006"],
    )


def _build_evidence(record: dict[str, Any], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "kind": "evil_winrm_session",
        "host": record.get("host"),
        "exit_code": record.get("exit_code"),
        "last_command": redact_hash_string(str(record.get("last_command") or "")),
        "last_cwd": record.get("last_cwd"),
        "errors": [redact_hash_string(err) for err in record.get("errors") or []],
    }
    cleaned: dict[str, Any] = {}
    for key, value in payload.items():
        if value in (None, "", []):
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
            "evil_winrm_parser.evidence_sidecar_write_failed",
            extra={
                "event": "evil_winrm_parser_sidecar_write_failed",
                "tool_id": tool_id,
                "artifacts_dir": str(artifacts_dir),
                "error_type": type(exc).__name__,
            },
        )


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_evil_winrm",
]
