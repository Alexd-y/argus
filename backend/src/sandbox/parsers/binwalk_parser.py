"""Parser for ``binwalk`` text output (ARG-032 batch 4b).

The catalog ``binwalk`` tool persists a tabular text log to
``/out/binwalk.log`` and the extracted artefacts under
``/out/binwalk/_<file>.extracted/``.  Canonical line shape::

    DECIMAL       HEXADECIMAL     DESCRIPTION
    --------------------------------------------------------------------
    0             0x0             ELF, 64-bit LSB executable
    16384         0x4000          Linux kernel version "5.15.0"
    65536         0x10000         gzip compressed data, ASCII, ...

Translation rules
-----------------

* One INFO finding per recognised signature row (CWE-200 — surface the
  embedded artefact for triage).  Severity LOW.
* One MISCONFIG finding per ``private key`` / ``RSA private key`` /
  ``PEM`` / ``OpenSSH private key`` signature row (CWE-321 / CWE-798).
  Critical: the actual private-key bytes are NEVER inlined; only the
  offset + signature label appear in evidence.

CRITICAL security gate
----------------------

Memory addresses (offsets in ``0x...`` form) are scrubbed via
:func:`scrub_evidence_strings` before sidecar persistence, so an
operator sees a pseudo-offset (``[REDACTED-ADDR]``) rather than a
filesystem-leaking absolute path.
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
)
from src.sandbox.parsers._base import (
    SENTINEL_CVSS_VECTOR,
    make_finding_dto,
    stable_hash_12,
)
from src.sandbox.parsers._jsonl_base import persist_jsonl_sidecar
from src.sandbox.parsers._text_base import (
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "binwalk_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("binwalk.log", "binwalk.txt")
_MAX_FINDINGS: Final[int] = 1_000

_SIGNATURE_RE: Final[re.Pattern[str]] = re.compile(
    r"^(?P<dec>\d+)\s+(?P<hex>0x[0-9a-fA-F]+)\s+(?P<description>.+)$"
)

_SECRET_KEYWORDS: Final[tuple[str, ...]] = (
    "private key",
    "rsa private key",
    "openssh private key",
    "pem",
    "pgp private",
    "pkcs8 unencrypted",
)

_DedupKey: TypeAlias = tuple[str, str]


def parse_binwalk(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate binwalk text output into FindingDTOs."""
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
        key: _DedupKey = (record["kind"], record["fingerprint"])
        if key in seen:
            continue
        seen.add(key)
        finding = _build_finding(record["kind"])
        keyed.append((key, finding, _serialise_evidence(record, tool_id=tool_id)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "binwalk.cap_reached",
                extra={
                    "event": "binwalk_cap_reached",
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
        line = raw_line.rstrip()
        if not line or line.startswith(("DECIMAL", "----")):
            continue
        match = _SIGNATURE_RE.match(line.strip())
        if match is None:
            continue
        description = match.group("description").strip()
        if not description:
            continue
        kind = "secret_artifact" if _is_secret_signature(description) else "signature"
        yield {
            "kind": kind,
            "fingerprint": stable_hash_12(f"{kind}|{description}"),
            "description": description,
            "offset_dec": match.group("dec"),
            "offset_hex": match.group("hex"),
        }


def _is_secret_signature(description: str) -> bool:
    lowered = description.lower()
    return any(token in lowered for token in _SECRET_KEYWORDS)


def _build_finding(kind: str) -> FindingDTO:
    if kind == "secret_artifact":
        return make_finding_dto(
            category=FindingCategory.SECRET_LEAK,
            cwe=[321, 798],
            cvss_v3_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            cvss_v3_score=7.8,
            confidence=ConfidenceLevel.LIKELY,
            owasp_wstg=["WSTG-CRYP-04"],
        )
    return make_finding_dto(
        category=FindingCategory.INFO,
        cwe=[200],
        cvss_v3_vector=SENTINEL_CVSS_VECTOR,
        cvss_v3_score=0.0,
        confidence=ConfidenceLevel.LIKELY,
        owasp_wstg=["WSTG-INFO-02"],
    )


def _serialise_evidence(record: dict[str, str], *, tool_id: str) -> str:
    payload: dict[str, Any] = {
        "tool_id": tool_id,
        "synthetic_id": stable_hash_12(
            f"{record.get('kind', '')}::{record.get('fingerprint', '')}"
        ),
        **record,
    }
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_binwalk",
]
