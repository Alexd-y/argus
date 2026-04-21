"""Parser for ``radare2 -j ij/iI/ii/iS/iz/is`` output (ARG-032 batch 4b).

The catalog ``radare2_info`` tool persists a compound JSON sidecar at
``/out/r2_info.json`` aggregating multiple ``r2 -c`` queries into a
single envelope::

    {
      "info":     { "core": { ... }, "bin": { "format": "elf64", ... } },
      "imports":  [ { "name": "system", "vaddr": "0x4012a0", ... } ],
      "exports":  [ { "name": "main",   "vaddr": "0x4011b0", ... } ],
      "sections": [ { "name": ".text",  "vaddr": "0x401000", "size": 1234,
                       "perm": "r-x", "entropy": 6.5 } ],
      "strings":  [ { "vaddr": "0x402000", "string": "/etc/passwd", ... } ]
    }

Translation rules
-----------------

* One INFO finding per dangerous import (``system``, ``execve``,
  ``strcpy``, ``gets``, ``memcpy`` family) — CWE-676 (Use of Potentially
  Dangerous Function).  Severity LOW — passive observation only.
* One MISCONFIG finding per ``rwx`` section (write+execute permissions
  set together) — CWE-693 (Protection Mechanism Failure).  Severity
  MEDIUM.
* One INFO finding per high-entropy section (entropy > 7.0) — CWE-200,
  often indicates packed / encrypted payload.

CRITICAL security gate
----------------------

Memory addresses (``0x[0-9a-fA-F]{8,}``) are scrubbed from every
evidence value before sidecar persistence so ASLR offsets do not leak
to downstream consumers.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final, TypeAlias

from src.pipeline.contracts.finding_dto import (
    ConfidenceLevel,
    FindingCategory,
    FindingDTO,
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import (
    load_canonical_or_stdout_json,
    persist_jsonl_sidecar,
)
from src.sandbox.parsers._text_base import scrub_evidence_strings

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "radare2_info_findings.jsonl"
_CANONICAL_FILENAME: Final[str] = "r2_info.json"
_MAX_FINDINGS: Final[int] = 1_000

# CWE-676 — Use of Potentially Dangerous Function.
_DANGEROUS_FUNCTIONS: Final[frozenset[str]] = frozenset(
    {
        "system",
        "popen",
        "execve",
        "execlp",
        "execvp",
        "strcpy",
        "strcat",
        "sprintf",
        "vsprintf",
        "gets",
        "scanf",
        "memcpy",
        "memmove",
        "tmpnam",
        "tempnam",
        "mktemp",
    }
)

_HIGH_ENTROPY_THRESHOLD: Final[float] = 7.0


_DedupKey: TypeAlias = tuple[str, str]


def parse_radare2_info(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate radare2 ``-j`` output into FindingDTOs."""
    del stderr
    payload = load_canonical_or_stdout_json(
        stdout=stdout,
        artifacts_dir=artifacts_dir,
        canonical_name=_CANONICAL_FILENAME,
        tool_id=tool_id,
    )
    if not isinstance(payload, dict):
        return []

    seen: set[_DedupKey] = set()
    keyed: list[tuple[_DedupKey, FindingDTO, str]] = []

    for record in _iter_dangerous_imports(payload):
        key: _DedupKey = ("import", record["name"])
        if key in seen:
            continue
        seen.add(key)
        finding = _build_dangerous_import_finding()
        keyed.append((key, finding, _serialise_evidence(record, tool_id=tool_id)))
        if len(keyed) >= _MAX_FINDINGS:
            break

    if len(keyed) < _MAX_FINDINGS:
        for record in _iter_rwx_sections(payload):
            key = ("section_rwx", record["name"])
            if key in seen:
                continue
            seen.add(key)
            finding = _build_rwx_section_finding()
            keyed.append((key, finding, _serialise_evidence(record, tool_id=tool_id)))
            if len(keyed) >= _MAX_FINDINGS:
                break

    if len(keyed) < _MAX_FINDINGS:
        for record in _iter_high_entropy_sections(payload):
            key = ("section_entropy", record["name"])
            if key in seen:
                continue
            seen.add(key)
            finding = _build_entropy_finding()
            keyed.append((key, finding, _serialise_evidence(record, tool_id=tool_id)))
            if len(keyed) >= _MAX_FINDINGS:
                _logger.warning(
                    "radare2_info.cap_reached",
                    extra={
                        "event": "radare2_info_cap_reached",
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


def _iter_dangerous_imports(payload: dict[str, Any]) -> Iterable[dict[str, str]]:
    imports = payload.get("imports")
    if not isinstance(imports, list):
        return
    for entry in imports:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        normalised = name.strip().lstrip("_")
        if normalised in _DANGEROUS_FUNCTIONS:
            yield {
                "kind": "dangerous_import",
                "name": normalised,
                "vaddr": str(entry.get("vaddr", "")),
                "type": str(entry.get("type", "")),
            }


def _iter_rwx_sections(payload: dict[str, Any]) -> Iterable[dict[str, str]]:
    sections = payload.get("sections")
    if not isinstance(sections, list):
        return
    for entry in sections:
        if not isinstance(entry, dict):
            continue
        perm = entry.get("perm")
        name = entry.get("name")
        if not isinstance(perm, str) or not isinstance(name, str):
            continue
        if "w" in perm.lower() and "x" in perm.lower():
            yield {
                "kind": "rwx_section",
                "name": name,
                "perm": perm,
                "vaddr": str(entry.get("vaddr", "")),
            }


def _iter_high_entropy_sections(
    payload: dict[str, Any],
) -> Iterable[dict[str, str]]:
    sections = payload.get("sections")
    if not isinstance(sections, list):
        return
    for entry in sections:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        try:
            entropy = float(entry.get("entropy") or 0.0)
        except (TypeError, ValueError):
            continue
        if entropy > _HIGH_ENTROPY_THRESHOLD:
            yield {
                "kind": "high_entropy_section",
                "name": name,
                "entropy": f"{entropy:.2f}",
                "vaddr": str(entry.get("vaddr", "")),
            }


def _build_dangerous_import_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[676, 200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.LIKELY,
        owasp_wstg=["WSTG-INFO-02", "WSTG-INFO-08"],
    )


def _build_rwx_section_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.MISCONFIG,
        cwe=[693],
        cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L",
        cvss_v3_score=5.0,
        confidence=ConfidenceLevel.LIKELY,
        owasp_wstg=["WSTG-CONF-08"],
    )


def _build_entropy_finding() -> FindingDTO:
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.SUSPECTED,
        owasp_wstg=["WSTG-INFO-02"],
    )


def _serialise_evidence(record: dict[str, str], *, tool_id: str) -> str:
    payload: dict[str, object] = {
        "tool_id": tool_id,
        "synthetic_id": stable_hash_12(
            f"{record.get('kind', '')}::{record.get('name', '')}"
        ),
        **record,
    }
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_radare2_info",
]
