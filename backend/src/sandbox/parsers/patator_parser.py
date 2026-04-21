"""Parser for ``patator`` text output (ARG-032 batch 4c).

Patator (Sébastien Macke) writes one record per attempted credential
to ``/out/patator.log``.  Successful authentications surface with a
``status`` of ``Found`` (or a 200/302 HTTP code on the http_fuzz
module).  Canonical line shape::

    11:42:01 patator    INFO - 0   1   1   1.0 | host=10.0.0.1:user=root:pass=toor [Found] http://10.0.0.1
    11:42:02 patator    INFO - 0   2   1   1.0 | host=10.0.0.1:user=admin:pass=hunter2 [200]

CRITICAL security gate
----------------------

The ``pass=`` value is **redacted before** the FindingDTO is built and
**never** reaches the sidecar — only the password length and a
synthetic finger­print survive.
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
    load_canonical_or_stdout_text,
    scrub_evidence_strings,
)

_logger = logging.getLogger(__name__)


EVIDENCE_SIDECAR_NAME: Final[str] = "patator_findings.jsonl"
_CANONICAL_NAMES: Final[tuple[str, ...]] = ("patator.log", "patator.txt")
_MAX_FINDINGS: Final[int] = 1_000

# Patator success line: ``host=H:user=U:pass=P [Found|200|302]``
_CRED_RE: Final[re.Pattern[str]] = re.compile(
    r"host=(?P<host>[^\s:]+(?::\d+)?):"
    r"user=(?P<user>[^\s:]+):"
    r"pass=(?P<password>\S+)"
    r"\s+\[(?P<status>Found|200|201|202|204|301|302)\]",
    re.IGNORECASE,
)


_DedupKey: TypeAlias = tuple[str, str]


def parse_patator(
    stdout: bytes,
    stderr: bytes,
    artifacts_dir: Path,
    tool_id: str,
) -> list[FindingDTO]:
    """Translate patator text output into AUTH FindingDTOs."""
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
        key: _DedupKey = (record["host"], record["username"])
        if key in seen:
            continue
        seen.add(key)
        finding = build_credential_finding()
        evidence = build_credential_evidence(
            tool_id=tool_id,
            host=record["host"],
            service="patator",
            username=record["username"],
            password_length=int(record["password_length"]),
            extra={"status": record["status"]},
        )
        keyed.append((key, finding, _serialise(evidence)))
        if len(keyed) >= _MAX_FINDINGS:
            _logger.warning(
                "patator.cap_reached",
                extra={
                    "event": "patator_cap_reached",
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
        password = match.group("password")
        yield {
            "host": match.group("host").strip(),
            "username": match.group("user").strip(),
            "password_length": str(len(password)),
            "status": match.group("status"),
        }


def _serialise(payload: dict[str, object]) -> str:
    cleaned = scrub_evidence_strings(payload)
    return json.dumps(cleaned, sort_keys=True, ensure_ascii=False)


__all__ = [
    "EVIDENCE_SIDECAR_NAME",
    "parse_patator",
]
